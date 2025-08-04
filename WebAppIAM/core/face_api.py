import logging
import os
import time
import tempfile
from typing import Dict, List, Optional

import numpy as np
from django.conf import settings
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import AuditLog

logger = logging.getLogger(__name__)

# ==============================
# Settings helpers (with defaults)
# ==============================
def _get_cfg(name: str, default):
    return getattr(settings, name, default)

# Where to store per-user enrollment frames (images only; no embeddings)
ENROLL_DIR = _get_cfg("FACE_ENROLL_DIR", tempfile.gettempdir())

# DeepFace configuration
DEEPFACE_MODEL     = _get_cfg("DEEPFACE_MODEL_NAME", "ArcFace")
DEEPFACE_METRIC    = _get_cfg("DEEPFACE_DISTANCE_METRIC", "cosine")
DEEPFACE_DETECTOR  = _get_cfg("DEEPFACE_DETECTOR_BACKEND", "retinaface")
DEEPFACE_THRESHOLD = float(_get_cfg("DEEPFACE_THRESHOLD", 0.40))

# Circuit breaker / fallback
FACE_API_ENABLED   = bool(_get_cfg("FACE_API_ENABLED", True))

# Performance knobs (sampling only; no embeddings)
MAX_ENROLL_FRAMES  = int(_get_cfg("FACE_MAX_ENROLL_FRAMES", 5))   # store at most N frames from enrollment video
MAX_PROBE_FRAMES   = int(_get_cfg("FACE_MAX_PROBE_FRAMES", 2))    # use at most N frames from probe video
MAX_COMPARE_PAIRS  = int(_get_cfg("FACE_MAX_COMPARE_PAIRS", 12))  # cap total ref×probe comparisons
EARLY_EXIT_ON_PASS = bool(_get_cfg("FACE_EARLY_EXIT_ON_PASS", True))
_COMPARISON_WORKERS = int(_get_cfg("FACE_COMPARISON_WORKERS", 4))  # parallelism degree for verify comparisons

# ==============================
# Exceptions
# ==============================
class FaceAPIError(Exception):
    """Errors in the face-enroll/verify flow."""
    pass

# ==============================
# Health check
# ==============================
def check_face_api_status() -> bool:
    # Consider "up" if DeepFace can be imported
    try:
        _lazy_deepface()
        return True
    except Exception:
        return False

# ==============================
# Lazy imports & byte/frame helpers
# ==============================
def _lazy_cv2():
    try:
        import cv2
        return cv2
    except ImportError as e:
        raise FaceAPIError("Install opencv-python to handle video/images") from e

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
    raise FaceAPIError("Expected bytes or file-like object")

def _frames_from_video_bytes(video_bytes: bytes, max_frames: int) -> List[np.ndarray]:
    """
    Extract up to max_frames, sampled evenly across the video.
    """
    cv2 = _lazy_cv2()
    path: Optional[str] = None
    frames: List[np.ndarray] = []
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp.write(video_bytes)
            path = tmp.name
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            raise FaceAPIError("Could not open video")

        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if total <= 0:
            # Fallback: read sequentially up to max_frames
            count = 0
            while cap.isOpened() and count < max_frames:
                ret, frame = cap.read()
                if not ret:
                    break
                frames.append(frame)
                count += 1
        else:
            idxs = np.linspace(0, total - 1, num=min(max_frames, total), dtype=int).tolist()
            for target in idxs:
                cap.set(cv2.CAP_PROP_POS_FRAMES, int(target))
                ret, frame = cap.read()
                if ret:
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

def _sample_paths(paths: List[str], k: int) -> List[str]:
    if len(paths) <= k:
        return paths
    idxs = np.linspace(0, len(paths) - 1, num=k, dtype=int).tolist()
    return [paths[i] for i in idxs]

# ==============================
# Model bootstrap (warmup)
# ==============================
_MODEL = None  # cached backbone if ever needed for deeper reuse

def _load_model_once():
    """
    Build the DeepFace backbone once per process (for potential future extension).
    """
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    DeepFace = _lazy_deepface()
    t0 = time.perf_counter()
    try:
        _MODEL = DeepFace.build_model(DEEPFACE_MODEL)
        logger.info("DeepFace model '%s' loaded in %.2fs", DEEPFACE_MODEL, time.perf_counter() - t0)
    except Exception as e:
        logger.warning("Failed to build DeepFace model during warmup: %s", e)
        raise
    return _MODEL

# ==============================
# Public API
# ==============================
def warmup():
    """
    Preload deepface import; in no-embeddings path this is cheap and avoids first-request import latency.
    """
    try:
        _lazy_deepface()
        # optionally build model so internal weights/cache are loaded early
        try:
            _load_model_once()
        except Exception:
            pass
        logger.info("face_api warmup (no-embeddings) done")
    except Exception as e:
        logger.warning("face_api warmup failed (non-fatal): %s", e)

def enroll_face(user, face_media) -> str:
    """
    Enroll a user's face. Accepts image bytes or video bytes.
    - Samples up to MAX_ENROLL_FRAMES frames from video (or uses the single image).
    - Stores ONLY sampled frames as {idx}.jpg under the user's folder.
    - No embeddings are created or persisted.
    """
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face enrollment is disabled")

    raw = _ensure_bytes(face_media)
    user_dir = _hashed_dir(user.id)
    os.makedirs(user_dir, exist_ok=True)

    # Decode frames (sampled)
    if _is_video_bytes(raw):
        frames = _frames_from_video_bytes(raw, MAX_ENROLL_FRAMES)
    else:
        frames = [_load_image_from_bytes(raw)]

    if not frames:
        raise FaceAPIError("No frames extracted for enrollment")

    cv2 = _lazy_cv2()
    saved_count = 0
    for idx, frame in enumerate(frames[:MAX_ENROLL_FRAMES]):
        path = os.path.join(user_dir, f"{idx}.jpg")
        try:
            if cv2.imwrite(path, frame):
                saved_count += 1
        except Exception:
            # continue even if one frame fails
            pass

    # Record enrollment dir on user (reuse azure_face_id field)
    setattr(user, "azure_face_id", user_dir)
    user.save(update_fields=["azure_face_id"])

    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=f"Stored {saved_count} frame(s) in {user_dir}",
        ip_address="System"
    )
    logger.info("Enrolled %d frames for user %s → %s", saved_count, user.id, user_dir)
    return user_dir

def verify_face(user, face_media, use_fallback: bool = True, max_retries: int = 0) -> Dict:
    """
    Verify a user's face WITHOUT embeddings.
    - Loads stored enrollment frames (jpgs).
    - Samples a small number of probe frames.
    - Runs DeepFace.verify over bounded pairs in parallel, takes best distance.
    Returns: {'is_identical': bool, 'confidence': float}
      * 'confidence' is (1 - best_distance) clamped to [0, 1].
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

    # Load reference frame paths
    ref_paths = sorted(
        os.path.join(user_dir, fn)
        for fn in os.listdir(user_dir)
        if fn.lower().endswith(".jpg")
    )
    if not ref_paths:
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("No reference frames found")

    # Decode probe frames (sampled)
    raw = _ensure_bytes(face_media)
    try:
        if _is_video_bytes(raw):
            probe_frames = _frames_from_video_bytes(raw, MAX_PROBE_FRAMES)
        else:
            probe_frames = [_load_image_from_bytes(raw)]
    except Exception:
        logger.exception("Failed to decode probe media")
        raise FaceAPIError("Invalid image/video data")

    if not probe_frames:
        raise FaceAPIError("No frames available from probe")

    # Cap comparisons to avoid quadratic blow-up
    ref_paths = _sample_paths(ref_paths, max(1, min(MAX_ENROLL_FRAMES, MAX_COMPARE_PAIRS)))
    if len(ref_paths) * len(probe_frames) > MAX_COMPARE_PAIRS:
        probe_frames = probe_frames[: max(1, MAX_COMPARE_PAIRS // max(1, len(ref_paths)))]

    # Warm up DeepFace if not already
    try:
        _load_model_once()
    except Exception:
        pass  # fallback: will still attempt verify and may fail later

    DeepFace = _lazy_deepface()

    pairs = [(ref, probe) for ref in ref_paths for probe in probe_frames]
    best_distance: Optional[float] = None
    t_start = time.perf_counter()

    def compare_pair(ref_probe):
        ref, probe = ref_probe
        try:
            res = DeepFace.verify(
                img1_path=ref,
                img2_path=probe,
                model_name=DEEPFACE_MODEL,
                distance_metric=DEEPFACE_METRIC,
                detector_backend=DEEPFACE_DETECTOR,
                enforce_detection=False,
            )
            d = float(res.get("distance", 1.0))
            return d
        except Exception as e:
            logger.debug("Comparison failure %s vs probe: %s", ref, e)
            return None

    attempt = 0
    while attempt <= max_retries:
        attempt += 1
        current_best: Optional[float] = None
        early_break = False

        with ThreadPoolExecutor(max_workers=_COMPARISON_WORKERS) as executor:
            futures = {executor.submit(compare_pair, p): p for p in pairs}
            for future in as_completed(futures):
                d = future.result()
                if d is None:
                    continue
                if current_best is None or d < current_best:
                    current_best = d
                if EARLY_EXIT_ON_PASS and d <= DEEPFACE_THRESHOLD:
                    best_distance = d
                    early_break = True
                    break  # early accept

            if early_break:
                break  # got a good match, stop retrying

        if current_best is not None:
            if best_distance is None or current_best < best_distance:
                best_distance = current_best
        if best_distance is not None:
            break  # success, no further retries

        # backoff before next attempt
        time.sleep(0.25)

    elapsed = time.perf_counter() - t_start

    if best_distance is None:
        AuditLog.objects.create(
            user=user,
            action="FACE_VERIFICATION_FAILED",
            details=f"All {max_retries+1} attempts failed",
            ip_address="System"
        )
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("Face verification ultimately failed")

    similarity = max(0.0, min(1.0, 1.0 - best_distance))
    is_identical = best_distance <= DEEPFACE_THRESHOLD

    AuditLog.objects.create(
        user=user,
        action="FACE_VERIFIED",
        details=(
            f"{'PASSED' if is_identical else 'FAILED'} "
            f"(d={best_distance:.4f}, sim={similarity:.2%}, "
            f"refs={len(ref_paths)}, probes={len(probe_frames)}, "
            f"elapsed={elapsed:.2f}s)"
        ),
        ip_address="System"
    )
    return {"is_identical": is_identical, "confidence": similarity}
