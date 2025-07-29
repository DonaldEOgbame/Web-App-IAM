import logging
import os
import time
import tempfile
from typing import Dict, List

import numpy as np
from django.conf import settings
from django.core.cache import cache

from .models import AuditLog

logger = logging.getLogger(__name__)

# ==============================
# Settings helpers (with defaults)
# ==============================
def _get_cfg(name: str, default):
    return getattr(settings, name, default)

# Where to store per-user enrollment frames
ENROLL_DIR = _get_cfg("FACE_ENROLL_DIR", tempfile.gettempdir())

# DeepFace configuration
DEEPFACE_MODEL     = _get_cfg("DEEPFACE_MODEL_NAME", "ArcFace")
DEEPFACE_METRIC    = _get_cfg("DEEPFACE_DISTANCE_METRIC", "cosine")
DEEPFACE_DETECTOR  = _get_cfg("DEEPFACE_DETECTOR_BACKEND", "retinaface")
DEEPFACE_THRESHOLD = float(_get_cfg("DEEPFACE_THRESHOLD", 0.40))

# Circuit breaker / fallback
FACE_API_ENABLED = bool(_get_cfg("FACE_API_ENABLED", True))
REQ_TIMEOUT_OPS  = int(_get_cfg("REQUEST_TIMEOUT_OPS", 15))

# ==============================
# Exceptions
# ==============================
class FaceAPIError(Exception):
    """Errors in the face‑enroll/verify flow."""
    pass

# ==============================
# Health check stub (always OK)
# ==============================
def check_face_api_status() -> bool:
    # Local DeepFace never goes down
    return True

# ==============================
# Lazy imports & byte/frame helpers
# ==============================
def _lazy_cv2():
    try:
        import cv2
        return cv2
    except ImportError as e:
        raise FaceAPIError("Install opencv‑python to handle video/images") from e

def _lazy_deepface():
    try:
        from deepface import DeepFace
        return DeepFace
    except ImportError as e:
        raise FaceAPIError("Install deepface to perform face recognition") from e

def _is_video_bytes(head: bytes) -> bool:
    # Quick MP4/QuickTime hint
    return b"ftyp" in head[:64]

def _ensure_bytes(data) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if hasattr(data, "read"):
        return data.read()
    raise FaceAPIError("Expected bytes or file‑like object")

def _frames_from_video_bytes(video_bytes: bytes) -> List[np.ndarray]:
    cv2 = _lazy_cv2()
    path = None
    frames: List[np.ndarray] = []
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp.write(video_bytes)
            path = tmp.name
        cap = cv2.VideoCapture(path)
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
        cap.release()
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    return frames

def _load_image_from_bytes(data: bytes) -> np.ndarray:
    cv2 = _lazy_cv2()
    arr = np.frombuffer(data, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise FaceAPIError("Could not decode image data")
    return img

def _hashed_dir(user_id: int) -> str:
    import hashlib
    h = hashlib.sha256(str(user_id).encode()).hexdigest()
    return os.path.join(ENROLL_DIR, h)

# ==============================
# Public API
# ==============================
def enroll_face(user, face_media) -> str:
    """
    Enroll a user's face. Accepts image bytes or video bytes.
    Saves EVERY frame as a .jpg under a per‑user directory.
    """
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face enrollment is disabled")

    raw = _ensure_bytes(face_media)
    user_dir = _hashed_dir(user.id)
    os.makedirs(user_dir, exist_ok=True)

    saved = []
    try:
        if _is_video_bytes(raw):
            # video: extract all frames
            frames = _frames_from_video_bytes(raw)
            cv2 = _lazy_cv2()
            for idx, frame in enumerate(frames):
                path = os.path.join(user_dir, f"{idx}.jpg")
                cv2.imwrite(path, frame)
                saved.append(path)
        else:
            # single image
            path = os.path.join(user_dir, "0.jpg")
            with open(path, "wb") as f:
                f.write(raw)
            saved.append(path)
    except Exception as e:
        logger.exception("Enrollment saving failed for user %s", user.id)
        raise FaceAPIError("Failed to save enrollment media") from e

    # Record enrollment dir on user (reuse azure_face_id field)
    setattr(user, "azure_face_id", user_dir)
    user.save(update_fields=["azure_face_id"])

    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=f"Stored {len(saved)} frame(s) in {user_dir}",
        ip_address="System"
    )
    logger.info("Enrolled %d frames for user %s → %s", len(saved), user.id, user_dir)
    return user_dir

def verify_face(user, face_media, use_fallback: bool = True, max_retries: int = 2) -> Dict:
    """
    Verify a user's face against their enrolled frames using DeepFace.
    Returns {'is_identical': bool, 'confidence': float}.
    """
    if not FACE_API_ENABLED:
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("Face verification is disabled")

    user_dir = getattr(user, "azure_face_id", None)
    if not user_dir or not os.path.isdir(user_dir):
        logger.error("No enrollment for user %s", user.id)
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("User has no enrolled face")

    # load reference frames
    ref_paths = sorted(
        os.path.join(user_dir, fn)
        for fn in os.listdir(user_dir)
        if fn.lower().endswith(".jpg")
    )
    if not ref_paths:
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("No reference frames found")

    raw = _ensure_bytes(face_media)
    try:
        if _is_video_bytes(raw):
            probe_frames = _frames_from_video_bytes(raw)
        else:
            probe_frames = [_load_image_from_bytes(raw)]
    except Exception as e:
        logger.exception("Failed to decode probe media")
        raise FaceAPIError("Invalid image/video data") from e

    best_distance = None
    DeepFace = _lazy_deepface()

    for attempt in range(max_retries + 1):
        try:
            # compare every enrolled frame vs every probe frame
            for ref in ref_paths:
                for probe in probe_frames:
                    res = DeepFace.verify(
                        img1_path=ref,
                        img2_path=probe,
                        model_name=DEEPFACE_MODEL,
                        distance_metric=DEEPFACE_METRIC,
                        detector_backend=DEEPFACE_DETECTOR,
                        enforce_detection=False
                    )
                    d = float(res["distance"])
                    if best_distance is None or d < best_distance:
                        best_distance = d

            if best_distance is None:
                raise FaceAPIError("No valid comparisons made")

            similarity   = 1.0 - best_distance
            is_identical = best_distance <= DEEPFACE_THRESHOLD

            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=(
                    f"{'PASSED' if is_identical else 'FAILED'} "
                    f"(d={best_distance:.4f}, sim={similarity:.2%})"
                ),
                ip_address="System"
            )
            return {"is_identical": is_identical, "confidence": similarity}

        except Exception as e:
            logger.warning("Verify attempt %d failed: %s", attempt + 1, e)
            best_distance = None
            time.sleep(0.5)

    # all retries failed
    AuditLog.objects.create(
        user=user,
        action="FACE_VERIFICATION_FAILED",
        details=f"All {max_retries+1} attempts failed",
        ip_address="System"
    )
    if use_fallback:
        return {"confidence": 0.0, "fallback": True}
    raise FaceAPIError("Face verification ultimately failed")
