import logging
import os
import json
import time
import tempfile
from typing import Dict, List, Tuple, Optional

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
DEEPFACE_METRIC    = _get_cfg("DEEPFACE_DISTANCE_METRIC", "cosine")  # 'cosine' | 'euclidean' | 'euclidean_l2'
DEEPFACE_DETECTOR  = _get_cfg("DEEPFACE_DETECTOR_BACKEND", "retinaface")
DEEPFACE_THRESHOLD = float(_get_cfg("DEEPFACE_THRESHOLD", 0.40))

# Circuit breaker / fallback
FACE_API_ENABLED = bool(_get_cfg("FACE_API_ENABLED", True))
REQ_TIMEOUT_OPS  = int(_get_cfg("REQUEST_TIMEOUT_OPS", 15))  # seconds

# ==============================
# Performance knobs (safe defaults)
# ==============================
# At enroll: also precompute embeddings (speeds up first verification)
PRECOMPUTE_EMBED_AT_ENROLL = bool(_get_cfg("FACE_PRECOMPUTE_EMBED_AT_ENROLL", True))

# At verify: sample at most this many probe frames to compare against references
MAX_PROBE_FRAMES = int(_get_cfg("FACE_MAX_PROBE_FRAMES", 3))

# At verify: cap number of reference frames loaded (0 = no cap)
MAX_REF_FRAMES = int(_get_cfg("FACE_MAX_REF_FRAMES", 50))

# Skip dark/blur frames quickly (saves time on detector/embedding)
MIN_BRIGHTNESS = float(_get_cfg("FACE_MIN_BRIGHTNESS", 25.0))  # 0..255
MIN_SHARPNESS  = float(_get_cfg("FACE_MIN_SHARPNESS", 50.0))   # Laplacian variance

# Cache TTL for embeddings (memory cache). Disk cache is persistent.
EMBED_CACHE_TTL_SEC = int(_get_cfg("FACE_EMBED_CACHE_TTL_SEC", 3600))

# Filenames for sidecar data in the per-user dir
EMBED_INDEX_JSON = "embeddings.json"  # manifest of ref .npy files
META_JSON        = "meta.json"        # misc metadata (optional)


# ==============================
# Exceptions
# ==============================
class FaceAPIError(Exception):
    """Errors in the face-enroll/verify flow."""
    pass


# ==============================
# Lazy imports & helpers
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

# Global singletons (built lazily)
_MODEL = None
_DETECTOR_NAME = None

def _get_model():
    """
    Build (or reuse) the DeepFace model once. This avoids model rebuilds per call.
    """
    global _MODEL, _DETECTOR_NAME
    if _MODEL is None:
        DeepFace = _lazy_deepface()
        _MODEL = DeepFace.build_model(DEEPFACE_MODEL)
        _DETECTOR_NAME = DEEPFACE_DETECTOR
        logger.info("DeepFace model built and cached (model=%s, detector=%s)", DEEPFACE_MODEL, DEEPFACE_DETECTOR)
    return _MODEL

def _is_video_bytes(head: bytes) -> bool:
    # Quick MP4/QuickTime hint
    return b"ftyp" in head[:64]

def _ensure_bytes(data) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if hasattr(data, "read"):
        return data.read()
    raise FaceAPIError("Expected bytes or file-like object")

def _frames_from_video_bytes(video_bytes: bytes, cap_limit: Optional[int]=None) -> List[np.ndarray]:
    """
    Extract frames from video bytes.
    If cap_limit is set, sample approximately evenly to that many frames.
    """
    cv2 = _lazy_cv2()
    path = None
    frames: List[np.ndarray] = []
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp.write(video_bytes)
            path = tmp.name
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            cap.release()
            raise FaceAPIError("Could not open video stream")

        # Read all frames first (fast path); sample later if needed
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frames.append(frame)
        cap.release()

        if cap_limit and len(frames) > cap_limit:
            idxs = np.linspace(0, len(frames)-1, cap_limit).astype(int)
            frames = [frames[i] for i in idxs]
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

def _brightness_and_sharpness(img: np.ndarray) -> Tuple[float, float]:
    cv2 = _lazy_cv2()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    brightness = float(np.mean(gray))
    sharpness = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    return brightness, sharpness

def _should_use_frame(img: np.ndarray) -> bool:
    b, s = _brightness_and_sharpness(img)
    return (b >= MIN_BRIGHTNESS) and (s >= MIN_SHARPNESS)

def _metric_distance(a: np.ndarray, b: np.ndarray, metric: str) -> float:
    """
    Compute distance according to DEEPFACE_METRIC.
    a: (D,) embedding ; b: (N,D) embeddings
    returns min distance (float)
    """
    if metric == "cosine":
        # cosine distance = 1 - cosine similarity
        # Normalize to unit vectors
        a_n = a / (np.linalg.norm(a) + 1e-9)
        b_n = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-9)
        dists = 1.0 - np.dot(b_n, a_n)
    elif metric in ("euclidean", "euclidean_l2"):
        # Euclidean distance
        d = b - a[None, :]
        dists = np.sqrt(np.sum(d * d, axis=1))
        if metric == "euclidean_l2":
            # In DeepFace, 'euclidean_l2' often uses L2 normalized embeddings.
            # Our embeddings from DeepFace.represent are already normalized for ArcFace;
            # if not, this still works consistently as a distance measure.
            pass
    else:
        # Fallback to cosine
        a_n = a / (np.linalg.norm(a) + 1e-9)
        b_n = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-9)
        dists = 1.0 - np.dot(b_n, a_n)

    return float(np.min(dists)) if len(dists) else float("inf")

def _represent(img: np.ndarray) -> Optional[np.ndarray]:
    """
    Get embedding vector from image using DeepFace.represent with the cached model.
    Returns a 1D numpy array, or None if detection fails when enforce_detection=True.
    We use enforce_detection=False to keep behavior tolerant (like your original code).
    """
    DeepFace = _lazy_deepface()
    model = _get_model()
    try:
        reps = DeepFace.represent(
            img_path = img,
            model_name = DEEPFACE_MODEL,
            detector_backend = _DETECTOR_NAME,
            enforce_detection = False,
            model = model,                # reuse the cached model
            align = True,
        )
        # DeepFace.represent may return list of dicts
        if isinstance(reps, list) and reps:
            emb = reps[0].get("embedding", None)
            if emb is not None:
                return np.asarray(emb, dtype=np.float32)
        return None
    except Exception as e:
        logger.debug("DeepFace.represent failed: %s", e)
        return None

def _load_or_compute_ref_embeddings(user_dir: str, ref_paths: List[str]) -> np.ndarray:
    """
    For enrolled reference frames, load (or compute) embeddings and return (N,D) array.
    Uses both disk sidecar cache (.npy files listed in embeddings.json) and Django cache.
    """
    # 1) Fast path: in-memory cache (Django cache)
    mem_key = f"face_ref_embeds::{user_dir}"
    cached = cache.get(mem_key)
    if isinstance(cached, np.ndarray) and cached.ndim == 2 and cached.shape[0] > 0:
        return cached

    # 2) Disk sidecar cache
    idx_path = os.path.join(user_dir, EMBED_INDEX_JSON)
    embeds: List[np.ndarray] = []

    if os.path.exists(idx_path):
        try:
            with open(idx_path, "r", encoding="utf-8") as f:
                index = json.load(f)
            # index = {"embeddings": [{"jpg": "0.jpg", "npy": "0.npy"}, ...]}
            for item in index.get("embeddings", []):
                npy_path = os.path.join(user_dir, item.get("npy", ""))
                if os.path.isfile(npy_path):
                    arr = np.load(npy_path)
                    if arr.ndim == 1:
                        embeds.append(arr.astype(np.float32))
        except Exception as e:
            logger.warning("Failed reading embeddings index for %s: %s", user_dir, e)

    # 3) Any missing embeddings -> compute now and update disk cache
    known_jpgs = {os.path.basename(p.get("jpg", "")) for p in index.get("embeddings", [])} if 'index' in locals() else set()
    missing = []
    for p in ref_paths:
        jpg = os.path.basename(p)
        if not known_jpgs or (jpg not in known_jpgs):
            missing.append(p)

    if missing:
        os.makedirs(user_dir, exist_ok=True)
        # Ensure index structure
        index = index if 'index' in locals() and isinstance(index, dict) else {"embeddings": []}

        for p in missing:
            try:
                img = _lazy_cv2().imread(p)
                if img is None:
                    continue
                if not _should_use_frame(img):
                    continue
                emb = _represent(img)
                if emb is None:
                    continue
                # Save to disk .npy
                base = os.path.splitext(os.path.basename(p))[0]
                npy_name = f"{base}.npy"
                npy_path = os.path.join(user_dir, npy_name)
                np.save(npy_path, emb)
                index["embeddings"].append({"jpg": os.path.basename(p), "npy": npy_name})
                embeds.append(emb.astype(np.float32))
            except Exception as e:
                logger.debug("Embedding compute failed for %s: %s", p, e)

        # Persist updated index
        try:
            with open(idx_path, "w", encoding="utf-8") as f:
                json.dump(index, f)
        except Exception as e:
            logger.warning("Failed writing embeddings index for %s: %s", user_dir, e)

    # 4) If we still have no embeddings (e.g., all frames too dark), try computing
    #    from the original list anyway (fallback without filters).
    if not embeds:
        for p in ref_paths:
            try:
                img = _lazy_cv2().imread(p)
                if img is None:
                    continue
                emb = _represent(img)
                if emb is None:
                    continue
                embeds.append(emb.astype(np.float32))
            except Exception as e:
                logger.debug("Fallback represent failed for %s: %s", p, e)

    if not embeds:
        return np.zeros((0, 512), dtype=np.float32)  # ArcFace = 512 dims (typical); keeps shape consistent

    arr = np.vstack(embeds)
    cache.set(mem_key, arr, timeout=EMBED_CACHE_TTL_SEC)
    return arr


# ==============================
# Health check stub (always OK)
# ==============================
def check_face_api_status() -> bool:
    # Local DeepFace never goes down
    return True


# ==============================
# Public API
# ==============================
def enroll_face(user, face_media) -> str:
    """
    Enroll a user's face. Accepts image bytes or video bytes.
    Writes frames as .jpg under a per-user directory (unchanged).
    Additionally (optional), computes & stores embeddings to speed up verification.
    """
    if not FACE_API_ENABLED:
        raise FaceAPIError("Face enrollment is disabled")

    raw = _ensure_bytes(face_media)
    user_dir = _hashed_dir(user.id)
    os.makedirs(user_dir, exist_ok=True)

    saved: List[str] = []
    try:
        if _is_video_bytes(raw):
            # Extract all frames (unchanged behavior), but we still skip write of totally invalid frames
            frames = _frames_from_video_bytes(raw)
            cv2 = _lazy_cv2()
            for idx, frame in enumerate(frames):
                if frame is None:
                    continue
                path = os.path.join(user_dir, f"{idx}.jpg")
                # Keep behavior: write all frames; but guard invalid frames
                ok = cv2.imwrite(path, frame)
                if ok:
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
    try:
        user.save(update_fields=["azure_face_id"])
    except Exception:
        # Fallback if update_fields mismatch; keep compatibility
        user.save()

    # Optionally precompute embeddings now (faster first verification)
    if PRECOMPUTE_EMBED_AT_ENROLL and saved:
        try:
            # Cap the number of frames we embed to a sane limit for speed, but keep all jpgs intact.
            ref_paths = sorted(
                p for p in saved if p.lower().endswith(".jpg")
            )
            if MAX_REF_FRAMES and len(ref_paths) > MAX_REF_FRAMES:
                # keep an even sampling
                idxs = np.linspace(0, len(ref_paths)-1, MAX_REF_FRAMES).astype(int)
                ref_paths = [ref_paths[i] for i in idxs]
            _ = _load_or_compute_ref_embeddings(user_dir, ref_paths)
        except Exception as e:
            logger.debug("Precompute embeddings failed for user %s: %s", user.id, e)

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
    Optimized to use cached model + embeddings; vectorized distance computation.
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

    # Load list of reference frames
    ref_paths = sorted(
        os.path.join(user_dir, fn)
        for fn in os.listdir(user_dir)
        if fn.lower().endswith(".jpg")
    )
    if not ref_paths:
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("No reference frames found")

    # Cap reference frames for speed (we still keep all files on disk; this only affects verification time)
    if MAX_REF_FRAMES and len(ref_paths) > MAX_REF_FRAMES:
        idxs = np.linspace(0, len(ref_paths)-1, MAX_REF_FRAMES).astype(int)
        ref_paths = [ref_paths[i] for i in idxs]

    # Decode probe media
    raw = _ensure_bytes(face_media)
    try:
        if _is_video_bytes(raw):
            probe_frames = _frames_from_video_bytes(raw, cap_limit=MAX_PROBE_FRAMES or None)
        else:
            probe_frames = [_load_image_from_bytes(raw)]
    except Exception as e:
        logger.exception("Failed to decode probe media")
        raise FaceAPIError("Invalid image/video data") from e

    # Filter unusable probe frames quickly
    filtered_probes = [img for img in probe_frames if img is not None and _should_use_frame(img)]
    if not filtered_probes:
        # If all are too dark/blur, fall back to first valid decode(s)
        filtered_probes = [img for img in probe_frames if img is not None]
        if not filtered_probes:
            if use_fallback:
                return {"confidence": 0.0, "fallback": True}
            raise FaceAPIError("No usable probe frames")

    # Load or compute enrolled embeddings once
    ref_embeds = _load_or_compute_ref_embeddings(user_dir, ref_paths)
    if ref_embeds.size == 0:
        if use_fallback:
            return {"confidence": 0.0, "fallback": True}
        raise FaceAPIError("No usable reference embeddings")

    best_distance = None
    deadline = time.time() + max(REQ_TIMEOUT_OPS, 3)

    for attempt in range(max_retries + 1):
        try:
            # Compute probe embeddings
            probe_embeds: List[np.ndarray] = []
            for img in filtered_probes:
                if time.time() > deadline:
                    break
                emb = _represent(img)
                if emb is not None:
                    probe_embeds.append(emb.astype(np.float32))

            if not probe_embeds:
                raise FaceAPIError("Failed to compute probe embeddings")

            # Vectorized: for each probe, compute distance to all refs and track the minimum
            for pe in probe_embeds:
                d = _metric_distance(pe, ref_embeds, DEEPFACE_METRIC)
                if best_distance is None or d < best_distance:
                    best_distance = d

            if best_distance is None:
                raise FaceAPIError("No valid comparisons made")

            similarity   = 1.0 - best_distance if DEEPFACE_METRIC == "cosine" else 1.0 / (1.0 + best_distance)
            is_identical = (best_distance <= DEEPFACE_THRESHOLD) if DEEPFACE_METRIC != "cosine" else (best_distance <= DEEPFACE_THRESHOLD)

            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=(
                    f"{'PASSED' if is_identical else 'FAILED'} "
                    f"(d={best_distance:.4f}, sim={similarity:.2%})"
                ),
                ip_address="System"
            )
            return {"is_identical": is_identical, "confidence": float(similarity)}

        except Exception as e:
            logger.warning("Verify attempt %d failed for user %s: %s", attempt + 1, user.id, e)
            best_distance = None
            time.sleep(0.25)
            if time.time() > deadline:
                break

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
