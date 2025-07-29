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

# Directory where we save enrolled face images
ENROLL_DIR = _get_cfg("FACE_ENROLL_DIR", tempfile.gettempdir())

# DeepFace configuration
DEEPFACE_MODEL = _get_cfg("DEEPFACE_MODEL_NAME", "ArcFace")
DEEPFACE_METRIC = _get_cfg("DEEPFACE_DISTANCE_METRIC", "cosine")
DEEPFACE_DETECTOR = _get_cfg("DEEPFACE_DETECTOR_BACKEND", "retinaface")
DEEPFACE_THRESHOLD = float(_get_cfg("DEEPFACE_THRESHOLD", 0.40))

# Circuit breaker / fallback settings
FACE_API_ENABLED = bool(_get_cfg("FACE_API_ENABLED", True))
REQ_TIMEOUT_OPS = int(_get_cfg("REQUEST_TIMEOUT_OPS", 15))

# ==============================
# Exceptions
# ==============================

class FaceAPIError(Exception):
    """Exception raised for errors in the face-verification flow."""
    pass

# ==============================
# Health check stub (always OK)
# ==============================

def check_face_api_status() -> bool:
    # Local DeepFace invocation never goes down
    return True

# ==============================
# Helpers
# ==============================

def _hashed_dir(user_id: int) -> str:
    import hashlib

    h = hashlib.sha256(str(user_id).encode("utf-8")).hexdigest()
    return os.path.join(ENROLL_DIR, h)


def _lazy_cv2():
    try:
        import cv2  # type: ignore
        return cv2
    except Exception as e:
        raise FaceAPIError(
            "OpenCV is required for video operations. Install opencv-python-headless"
        ) from e


def _lazy_deepface():
    try:
        from deepface import DeepFace  # type: ignore
        return DeepFace
    except Exception as e:
        raise FaceAPIError(
            "DeepFace is required for face recognition. Install dependencies"
        ) from e


def _is_video_bytes(first_bytes: bytes) -> bool:
    return b"ftyp" in (first_bytes or b"")[:64]


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
            ok, frame = cap.read()
            if not ok:
                break
            frames.append(frame)
        cap.release()
    finally:
        if path:
            try:
                os.remove(path)
            except Exception:
                pass
    return frames


def _ensure_bytes(data) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if hasattr(data, "read"):
        return data.read()
    raise FaceAPIError("Invalid payload: expected bytes-like object")


def _load_image_from_bytes(data: bytes):
    cv2 = _lazy_cv2()
    nparr = np.frombuffer(data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("cv2.imdecode returned None")
    return img

# ==============================
# Public API
# ==============================

def enroll_face(user, face_image_bytes) -> str:
    """Enroll a user's face. Accepts image bytes or video bytes."""
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face enrollment is disabled")

    os.makedirs(ENROLL_DIR, exist_ok=True)
    user_dir = _hashed_dir(user.id)
    os.makedirs(user_dir, exist_ok=True)

    raw = _ensure_bytes(face_image_bytes)

    saved: List[str] = []
    try:
        if _is_video_bytes(raw[:64]):
            frames = _frames_from_video_bytes(raw)
            for i, frame in enumerate(frames):
                path = os.path.join(user_dir, f"{i}.jpg")
                _lazy_cv2().imwrite(path, frame)
                saved.append(path)
        else:
            path = os.path.join(user_dir, "0.jpg")
            with open(path, "wb") as f:
                f.write(raw)
            saved.append(path)
    except Exception as e:
        logger.exception("Failed to save enrollment media for user %s", user.id)
        raise FaceAPIError("Could not save enrollment media") from e

    setattr(user, "azure_face_id", user_dir)
    user.save(update_fields=["azure_face_id"])

    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=f"Enrollment stored {len(saved)} frame(s) in {user_dir}",
        ip_address="System",
    )
    logger.info(
        "Face enrollment successful for user %s → %s frames", user.id, len(saved)
    )
    return user_dir


def verify_face(user, face_image_bytes, use_fallback: bool = True, max_retries: int = 2) -> Dict:
    """Verify a user's face against their enrolled reference using DeepFace."""
    if not FACE_API_ENABLED:
        logger.warning("Face API is disabled, using fallback")
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("Face verification is disabled")

    ref_dir = getattr(user, "azure_face_id", None)
    if not ref_dir or not os.path.isdir(ref_dir):
        logger.error("User %s has no enrolled face images", user.id)
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("User has no enrolled face")

    ref_images = [
        os.path.join(ref_dir, f)
        for f in os.listdir(ref_dir)
        if f.lower().endswith(".jpg")
    ]
    if not ref_images:
        logger.error("No reference images for user %s", user.id)
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("User has no enrolled face")

    raw = _ensure_bytes(face_image_bytes)
    try:
        if _is_video_bytes(raw[:64]):
            probe_frames = _frames_from_video_bytes(raw)
        else:
            probe_frames = [_load_image_from_bytes(raw)]
    except Exception as e:
        logger.exception("Failed to decode probe media")
        raise FaceAPIError("Invalid image data") from e

    last_error = None
    best_distance = None
    for attempt in range(max_retries + 1):
        try:
            df = _lazy_deepface()
            for ref_path in ref_images:
                for frame in probe_frames:
                    res = df.verify(
                        img1_path=ref_path,
                        img2_path=frame,
                        model_name=DEEPFACE_MODEL,
                        distance_metric=DEEPFACE_METRIC,
                        detector_backend=DEEPFACE_DETECTOR,
                        enforce_detection=False,
                    )
                    distance = float(res["distance"])
                    if best_distance is None or distance < best_distance:
                        best_distance = distance
            if best_distance is None:
                raise FaceAPIError("No frames processed")
            similarity = 1.0 - best_distance
            is_identical = best_distance <= DEEPFACE_THRESHOLD

            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=(
                    f"verification {'passed' if is_identical else 'failed'} "
                    f"(distance={best_distance:.4f}, similarity={similarity:.2%})"
                ),
                ip_address="System",
            )
            return {"is_identical": is_identical, "confidence": similarity}
        except Exception as e:
            last_error = e
            logger.warning("DeepFace verify attempt %d failed: %s", attempt + 1, e)
            time.sleep(0.5)

    AuditLog.objects.create(
        user=user,
        action="FACE_VERIFICATION_FAILED",
        details=f"Failed after {max_retries + 1} attempts: {last_error}",
        ip_address="System",
    )
    if use_fallback:
        logger.warning(
            "Using fallback for user %s after repeated DeepFace failures", user.id
        )
        return {"confidence": 0.0, "fallback": True}
    raise FaceAPIError(f"Face verification failed: {last_error}")
