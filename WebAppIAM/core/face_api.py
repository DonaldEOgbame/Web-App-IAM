import logging
import time
import tempfile
from typing import List, Tuple

import requests
from django.conf import settings
from django.core.cache import cache

from .models import AuditLog

logger = logging.getLogger(__name__)

# ==============================
# Exceptions
# ==============================
class FaceAPIError(Exception):
    """Exception raised for errors in the Face API (CompreFace backend)."""
    pass


# ==============================
# Settings helpers (with defaults)
# ==============================
def _get_cfg(name: str, default):
    return getattr(settings, name, default)


COMPRE_BASE = _get_cfg("COMPRESPACE_API_BASE", "http://localhost:8000/api").rstrip("/")
COMPRE_KEY = _get_cfg("COMPRESPACE_API_KEY", "")
DET_PROB_THR = float(_get_cfg("COMPRESPACE_DET_PROB_THRESHOLD", 0.85))
RECOG_THR = float(_get_cfg("COMPRESPACE_RECOGNITION_THRESHOLD", 0.75))

# Video enrollment knobs
ENROLL_VIDEO_ENABLED = bool(_get_cfg("ENROLL_VIDEO_ENABLED", True))
ENROLL_VIDEO_SAMPLE_FPS = float(_get_cfg("ENROLL_VIDEO_SAMPLE_FPS", 3.0))
ENROLL_VIDEO_MAX_FRAMES = int(_get_cfg("ENROLL_VIDEO_MAX_FRAMES", 30))
ENROLL_VIDEO_TOP_K = int(_get_cfg("ENROLL_VIDEO_TOP_K", 5))
ENROLL_FACE_MIN_SIDE = int(_get_cfg("ENROLL_FACE_MIN_SIDE", 180))
ENROLL_SHARPNESS_MIN = float(_get_cfg("ENROLL_SHARPNESS_MIN", 80.0))

REQ_TIMEOUT_HEALTH = int(_get_cfg("REQUEST_TIMEOUT_HEALTH", 5))
REQ_TIMEOUT_OPS = int(_get_cfg("REQUEST_TIMEOUT_OPS", 15))

FACE_API_ENABLED = bool(_get_cfg("FACE_API_ENABLED", True))

# ==============================
# Circuit breaker helpers
# ==============================
def _record_failure():
    count = cache.get("face_api_failure_count", 0) + 1
    cache.set("face_api_failure_count", count, 300)
    if count >= 3:
        cache.set("face_api_circuit_until", time.time() + 300, 300)


def _reset_failures():
    cache.set("face_api_failure_count", 0, 300)
    cache.delete("face_api_circuit_until")


# ==============================
# Client helper (compatibility)
# ==============================
def get_face_client():
    """Return a minimal client compatible with older tests."""

    class _PersonGroup:
        def list(self):
            # Use the CompreFace health endpoint as a lightweight check
            r = requests.get(
                f"{COMPRE_BASE}/v1/management/health",
                headers=_headers(),
                timeout=REQ_TIMEOUT_HEALTH,
            )
            if r.status_code >= 500:
                raise FaceAPIError(f"Health check failed: {r.status_code}")
            return []

    class _Client:
        def __init__(self):
            self.person_group = _PersonGroup()

    return _Client()


# ==============================
# CompreFace low-level helpers
# ==============================
def _headers() -> dict:
    return {"x-api-key": COMPRE_KEY} if COMPRE_KEY else {}


def _compreface_health_ok() -> bool:
    # Try management health endpoint first (CompreFace default), fall back to a trivial GET.
    urls = [
        f"{COMPRE_BASE}/v1/management/health",
        f"{COMPRE_BASE}/v1/recognition/config",
    ]
    for u in urls:
        try:
            r = requests.get(u, headers=_headers(), timeout=REQ_TIMEOUT_HEALTH)
            if r.status_code < 500:
                return True
        except Exception:
            continue
    return False


# ==============================
# Public health check
# ==============================
def check_face_api_status() -> bool:
    """Check if the Face (CompreFace) API is available and circuit isn't open."""
    if not FACE_API_ENABLED:
        return False

    circuit_until = cache.get("face_api_circuit_until")
    if circuit_until and circuit_until > time.time():
        return False

    try:
        client = get_face_client()
        client.person_group.list()
        _reset_failures()
        return True
    except Exception:
        logger.exception("CompreFace health check failed")
        _record_failure()
        return False


# ==============================
# Video utilities (lazy OpenCV)
# ==============================
def _lazy_cv2():
    try:
        import cv2  # type: ignore
        return cv2
    except Exception as e:
        raise FaceAPIError(
            "Video enrollment requires opencv-python. Install with: pip install opencv-python"
        ) from e


def _var_laplacian(gray, cv2):
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())


def _jpeg_bytes(frame, cv2, quality: int = 90) -> bytes:
    ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, int(quality)])
    if not ok:
        raise FaceAPIError("Failed to encode JPEG from video frame")
    return buf.tobytes()


def _is_video_bytes(first_bytes: bytes) -> bool:
    # Rough heuristic: MP4/QuickTime contain 'ftyp' early in file.
    return b"ftyp" in (first_bytes or b"")[:64]


def _frames_from_video_bytes(video_bytes: bytes, sample_fps: float, max_frames: int):
    cv2 = _lazy_cv2()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
        f.write(video_bytes)
        path = f.name
    try:
        cap = cv2.VideoCapture(path)
        fps = cap.get(cv2.CAP_PROP_FPS) or 24.0
        step = max(int(round(fps / max(sample_fps, 0.1))), 1)
        kept = i = 0
        while cap.isOpened() and kept < max_frames:
            ok = cap.grab()
            if not ok:
                break
            if i % step == 0:
                ok, frame = cap.retrieve()
                if not ok:
                    break
                kept += 1
                yield frame
            i += 1
    finally:
        try:
            cap.release()
        except Exception:
            pass
        try:
            import os
            os.remove(path)
        except Exception:
            pass


def _coarse_quality_ok(frame, min_side: int, min_sharp: float, cv2) -> tuple[bool, float]:
    h, w = frame.shape[:2]
    if min(h, w) < min_side:
        return False, 0.0
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    sharp = _var_laplacian(gray, cv2)
    if sharp < min_sharp:
        return False, sharp
    return True, sharp


# ==============================
# High-level CompreFace flows
# ==============================
def _compreface_enroll_image(subject: str, img_bytes: bytes) -> None:
    r = requests.post(
        f"{COMPRE_BASE}/v1/recognition/faces",
        headers=_headers(),
        files={"file": ("enroll.jpg", img_bytes, "image/jpeg")},
        data={"subject": subject},
        timeout=REQ_TIMEOUT_OPS,
    )
    if r.status_code >= 300:
        try:
            j = r.json()
        except Exception:
            j = {}
        raise FaceAPIError(f"Enroll failed: {r.status_code} {j}")


def _compreface_verify_subject(subject: str, img_bytes: bytes) -> float:
    """Returns similarity in [0,1] as confidence."""
    r = requests.post(
        f"{COMPRE_BASE}/v1/verification/subjects/{subject}",
        headers=_headers(),
        files={"file": ("verify.jpg", img_bytes, "image/jpeg")},
        params={"det_prob_threshold": DET_PROB_THR},
        timeout=REQ_TIMEOUT_OPS,
    )
    if r.status_code == 404:
        # subject not found → treat as 0 confidence
        return 0.0
    if r.status_code >= 300:
        try:
            j = r.json()
        except Exception:
            j = {}
        raise FaceAPIError(f"Verify failed: {r.status_code} {j}")
    data = r.json() or {}
    res = (data.get("result") or [{}])[0]
    return float(res.get("similarity", 0.0))


def _enroll_from_video_bytes_compreface(subject: str, video_bytes: bytes) -> int:
    """Extract frames; enroll top-K by (similarity, sharpness)."""
    cv2 = _lazy_cv2()
    candidates: List[Tuple[float, float, bytes]] = []  # (similarity, sharpness, jpeg)

    for frame in _frames_from_video_bytes(video_bytes, ENROLL_VIDEO_SAMPLE_FPS, ENROLL_VIDEO_MAX_FRAMES):
        ok, sharp = _coarse_quality_ok(frame, ENROLL_FACE_MIN_SIDE, ENROLL_SHARPNESS_MIN, cv2)
        if not ok:
            continue
        jpg = _jpeg_bytes(frame, cv2)
        try:
            sim = _compreface_verify_subject(subject, jpg)
        except Exception:
            # Skip frame on transient errors
            continue
        candidates.append((sim, sharp, jpg))

    if not candidates:
        raise FaceAPIError("No suitable frames found in video")

    candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
    picked = candidates[:ENROLL_VIDEO_TOP_K]

    enrolled = 0
    for _, _, jpg in picked:
        try:
            _compreface_enroll_image(subject, jpg)
            enrolled += 1
        except Exception:
            continue

    if enrolled == 0:
        raise FaceAPIError("Enrollment failed for all frames")
    return enrolled


# ==============================
# Public API
# ==============================
def enroll_face(user, face_image_or_video_bytes: bytes):
    """
    Enroll a user's face using CompreFace.
    Accepts image bytes or short video bytes (MP4/MOV/WebM).
    """
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face API is disabled")

    # Health check & circuit breaker
    if not check_face_api_status():
        logger.error("Face API is currently unavailable")
        raise FaceAPIError("Face API is currently unavailable. Please try again later.")

    raw = face_image_or_video_bytes
    if not isinstance(raw, (bytes, bytearray)):
        raise FaceAPIError("Invalid payload: expected bytes")

    # Decide video vs image
    is_video = _is_video_bytes(raw[:64]) and ENROLL_VIDEO_ENABLED

    subject = str(user.id)  # Stable subject id
    if is_video:
        frames_enrolled = _enroll_from_video_bytes_compreface(subject, raw)
        details = f"Video enrollment: {frames_enrolled} frames added"
    else:
        # Treat bytes as image
        _compreface_enroll_image(subject, raw)
        details = "Image enrollment completed"

    # Persist ID in existing field to avoid migrations
    setattr(user, "azure_face_id", subject)
    user.save(update_fields=["azure_face_id"])

    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=details,
        ip_address="System"
    )
    logger.info("Face enrollment successful for user %s (%s)", user.id, details)
    return subject


def verify_face(user, face_image_bytes: bytes, use_fallback: bool = True, max_retries: int = 2):
    """
    Verify a user's face against their enrolled subject using CompreFace.
    Returns: {'is_identical': bool, 'confidence': float} (0..1), optionally {'fallback': True}
    """
    if not FACE_API_ENABLED:
        if use_fallback:
            logger.warning("Face API is disabled, using fallback authentication")
            return {"confidence": 0.7, "fallback": True}
        raise FaceAPIError("Face API is disabled")

    if not check_face_api_status():
        if use_fallback:
            logger.warning("Face API is unavailable, using fallback authentication")
            AuditLog.objects.create(
                user=user,
                action="FACE_API_UNAVAILABLE",
                details="Face API unavailable during verification, used fallback",
                ip_address="System"
            )
            return {"confidence": 0.6, "fallback": True}
        raise FaceAPIError("Face API is currently unavailable")

    if not getattr(user, "azure_face_id", None):
        logger.error("User %s doesn't have an enrolled face", user.id)
        if use_fallback:
            return {"confidence": 0.3, "fallback": True}
        raise FaceAPIError("User doesn't have an enrolled face")

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            conf = _compreface_verify_subject(user.azure_face_id, face_image_bytes)
            is_identical = conf >= RECOG_THR

            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=f"Face verification {'passed' if is_identical else 'failed'} (confidence: {conf:.2f})",
                ip_address="System"
            )
            return {"is_identical": bool(is_identical), "confidence": float(conf)}
        except Exception as e:
            last_error = e
            logger.warning("Face verification attempt %d failed: %s", attempt + 1, e)

    AuditLog.objects.create(
        user=user,
        action="FACE_VERIFICATION_FAILED",
        details=f"Face verification failed after {max_retries+1} attempts: {last_error}",
        ip_address="System"
    )

    if use_fallback and _get_cfg("RISK_ENGINE_BYPASS", False):
        logger.warning("Face API failed, using fallback authentication for user %s", user.id)
        return {"confidence": 0.5, "fallback": True}

    raise FaceAPIError(f"Face verification failed: {last_error}")
