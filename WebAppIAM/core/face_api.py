import logging
import os
import time
import tempfile
from typing import Dict

import numpy as np
import cv2
from deepface import DeepFace
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

def _hashed_filename(user_id: int, suffix: str = ".jpg") -> str:
    import hashlib

    h = hashlib.sha256(str(user_id).encode("utf-8")).hexdigest()
    return os.path.join(ENROLL_DIR, f"{h}{suffix}")


def _load_image_from_bytes(data: bytes):
    nparr = np.frombuffer(data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("cv2.imdecode returned None")
    return img

# ==============================
# Public API
# ==============================

def enroll_face(user, face_image_bytes: bytes) -> str:
    """Enroll a user's face by saving the image locally."""
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face enrollment is disabled")

    os.makedirs(ENROLL_DIR, exist_ok=True)
    path = _hashed_filename(user.id)
    try:
        with open(path, "wb") as f:
            f.write(face_image_bytes)
    except Exception as e:
        logger.exception("Failed to save enrollment image for user %s", user.id)
        raise FaceAPIError("Could not save enrollment image") from e

    setattr(user, "azure_face_id", path)
    user.save(update_fields=["azure_face_id"])

    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=f"Enrollment image saved to {path}",
        ip_address="System",
    )
    logger.info("Face enrollment successful for user %s → %s", user.id, path)
    return path


def verify_face(user, face_image_bytes: bytes, use_fallback: bool = True, max_retries: int = 2) -> Dict:
    """Verify a user's face against their enrolled reference using DeepFace."""
    if not FACE_API_ENABLED:
        logger.warning("Face API is disabled, using fallback")
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("Face verification is disabled")

    ref_path = getattr(user, "azure_face_id", None)
    if not ref_path or not os.path.isfile(ref_path):
        logger.error("User %s has no enrolled face image", user.id)
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("User has no enrolled face")

    try:
        probe_img = _load_image_from_bytes(face_image_bytes)
    except Exception as e:
        logger.exception("Failed to decode probe image bytes")
        raise FaceAPIError("Invalid image data") from e

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            res = DeepFace.verify(
                img1_path=ref_path,
                img2_path=probe_img,
                model_name=DEEPFACE_MODEL,
                distance_metric=DEEPFACE_METRIC,
                detector_backend=DEEPFACE_DETECTOR,
                enforce_detection=False,
            )
            distance = float(res["distance"])
            similarity = 1.0 - distance
            is_identical = distance <= DEEPFACE_THRESHOLD

            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=(
                    f"verification {'passed' if is_identical else 'failed'} "
                    f"(distance={distance:.4f}, similarity={similarity:.2%})"
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
