# risk_engine.py
import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
if project_root not in sys.path:
    sys.path.append(project_root)

import json
import joblib
import numpy as np
import logging
import threading
from typing import Optional, Sequence
from django.conf import settings
import time

logger = logging.getLogger(__name__)

# -------- Model locations (UNCHANGED) --------
ML_MODELS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ml_pipeline", "models", "production")
)

# -------- Lazy globals --------
risk_model = None
risk_meta = {}
behavior_model = None
behavior_meta = {}
_loaded = False
_lock = threading.Lock()

# Neutral default when keystrokes are unavailable or insufficient
KEYSTROKE_NEUTRAL = 0.5


def _load_models():
    """
    Thread-safe loader for risk/behavior models.
    Uses joblib's mmap_mode for faster loads of large numpy arrays where applicable.
    """
    global _loaded, risk_model, risk_meta, behavior_model, behavior_meta
    if _loaded:
        return
    with _lock:
        if _loaded:
            return

        t0 = time.perf_counter()

        # ------- Risk model -------
        try:
            risk_path = os.path.join(ML_MODELS_DIR, "risk_model.pkl")
            risk_meta_path = os.path.join(ML_MODELS_DIR, "risk_model_meta.json")
            if not os.path.exists(risk_path):
                logger.error("Risk model file not found: %s", risk_path)
                raise FileNotFoundError(f"Risk model file not found: {risk_path}")
            if not os.path.exists(risk_meta_path):
                logger.error("Risk model meta file not found: %s", risk_meta_path)
                raise FileNotFoundError(f"Risk model meta file not found: {risk_meta_path}")

            # mmap_mode speeds up unpickling of arrays in many cases
            risk_model = joblib.load(risk_path, mmap_mode="r")
            with open(risk_meta_path, "r") as f:
                risk_meta = json.load(f)
            logger.info("Loaded risk model v%s", risk_meta.get("version"))
        except Exception as e:
            logger.error("Risk model loading failed: %s", e)
            risk_model, risk_meta = None, {}

        # ------- Behavior model -------
        try:
            behavior_path = os.path.join(ML_MODELS_DIR, "behavior_model.pkl")
            behavior_meta_path = os.path.join(ML_MODELS_DIR, "behavior_model_meta.json")
            if not os.path.exists(behavior_path):
                logger.error("Behavior model file not found: %s", behavior_path)
                raise FileNotFoundError(f"Behavior model file not found: {behavior_path}")
            if not os.path.exists(behavior_meta_path):
                logger.error("Behavior model meta file not found: %s", behavior_meta_path)
                raise FileNotFoundError(f"Behavior model meta file not found: {behavior_meta_path}")

            behavior_model = joblib.load(behavior_path, mmap_mode="r")
            with open(behavior_meta_path, "r") as f:
                behavior_meta = json.load(f)
            logger.info("Loaded behavior model v%s", behavior_meta.get("version"))
        except Exception as e:
            logger.error("Behavior model loading failed: %s", e)
            behavior_model, behavior_meta = None, {}

        _loaded = True
        t1 = time.perf_counter()
        logger.info("ML models load finished in %.3f s", t1 - t0)


def load_models():
    """
    Public wrapper returning loaded ML models for testing.

    Raises
    ------
    RuntimeError
        If either the risk or behavior model failed to load.
    """
    _load_models()
    if risk_model is None or behavior_model is None:
        raise RuntimeError("ML models not loaded")
    return risk_model, behavior_model


def warmup():
    """
    Optional: Preloads models and runs a minimal dummy inference to prime the pipeline.
    Call this once at process start (e.g., AppConfig.ready()).
    """
    _load_models()
    # Minimal arrays based on expected features (fall back to 4 for risk, 6 for behavior)
    rf = risk_meta.get("expected_features", ["face_match", "fingerprint_verified", "behavior_anomaly", "keystroke_anomaly"])
    bf = behavior_meta.get("expected_features",
                           ["time_anomaly", "device_anomaly", "location_anomaly", "action_entropy", "ip_risk", "session_duration"])

    try:
        if risk_model is not None:
            dummy_risk = _ordered_feature_row([0.0, 1.0, 0.5, KEYSTROKE_NEUTRAL], rf)
            _ = _predict_prob(risk_model, dummy_risk)
        if behavior_model is not None:
            # session_duration as a moderate value
            dummy_behavior = _ordered_feature_row([0.0, 0.0, 0.0, 0.5, 0.1, 300.0], bf)
            _ = _predict_prob(behavior_model, dummy_behavior)
        logger.info("Risk engine warmup completed.")
    except Exception as e:
        logger.warning("Warmup failed (non-fatal): %s", e)


def _assert_schema(n_cols: int, meta: dict):
    expected = meta.get("expected_features", [])
    if not expected:
        logger.warning("No expected_features in model meta; skipping schema check.")
        return
    if n_cols != len(expected):
        raise ValueError(f"Feature count mismatch: got {n_cols}, expected {len(expected)}")


def _safe01(x: Optional[float], default: float = 0.0) -> float:
    try:
        v = float(x)
        if np.isnan(v) or np.isinf(v):
            return default
        return float(np.clip(v, 0.0, 1.0))
    except Exception:
        return default


def _ordered_feature_row(values: Sequence[float], expected_names: Sequence[str]) -> np.ndarray:
    """
    Builds a (1, n) float32 row for scikit-learn from provided values,
    trimmed/padded to the expected feature count.
    """
    n = len(expected_names)
    arr = np.asarray(values, dtype=np.float32).reshape(1, -1)
    if arr.shape[1] < n:
        pad = np.zeros((1, n - arr.shape[1]), dtype=np.float32)
        arr = np.concatenate([arr, pad], axis=1)
    elif arr.shape[1] > n:
        arr = arr[:, :n]
    return arr


def _predict_prob(model, X: np.ndarray) -> float:
    """
    Predicts probability if available, otherwise clips regression output to [0,1].
    """
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        # proba shape: (1, 2) => take class-1 probability
        return float(proba[0, 1])
    pred = model.predict(X)
    return float(np.clip(pred[0], 0.0, 1.0))


def calculate_risk_score(face_match: float,
                         fingerprint_verified: bool,
                         behavior_anomaly: float,
                         keystroke_anomaly: Optional[float] = None) -> float:
    """
    Returns probability-like risk score in [0, 1].
    Accepts 4 inputs (face_match, fingerprint_verified, behavior_anomaly, keystroke_anomaly).
    Falls back to rule-based if model unavailable or inference fails.

    Notes
    -----
    - If keystroke_anomaly is None or invalid, uses neutral 0.5.
    - Strictly checks feature count against model meta's `expected_features`.
    """
    # Normalize inputs
    fm = _safe01(face_match, 0.0)
    fp = float(bool(fingerprint_verified))
    ba = _safe01(behavior_anomaly, 0.5)
    ka = _safe01(keystroke_anomaly, KEYSTROKE_NEUTRAL)

    # Try model path
    try:
        rm, _ = load_models()
    except RuntimeError:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    if rm is None:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    expected = risk_meta.get("expected_features", ["face_match", "fingerprint_verified", "behavior_anomaly", "keystroke_anomaly"])
    try:
        _assert_schema(4, {"expected_features": expected})
        feats = _ordered_feature_row([fm, fp, ba, ka], expected)
        return _predict_prob(rm, feats)
    except Exception as e:
        logger.exception("Risk model inference failed, fallback to rule: %s", e)
        return _rule_risk(fm, fp, ba, ka)


def analyze_behavior_anomaly(session) -> float:
    """
    Returns behavior anomaly score in [0, 1].
    Falls back to rule-based if model unavailable.
    """
    # Gather features with safe defaults
    t = _safe01(getattr(session, 'time_anomaly', 0.0), 0.0)        # 0..1
    d = _safe01(getattr(session, 'device_anomaly', 0.0), 0.0)      # 0/1
    l = _safe01(getattr(session, 'location_anomaly', 0.0), 0.0)    # 0..1
    e = _safe01(getattr(session, 'action_entropy', 0.5), 0.5)      # 0..1
    ip = _safe01(getattr(session, 'ip_risk', 0.1), 0.1)            # 0..1
    dur = float(getattr(session, 'session_duration', 300.0))       # seconds

    try:
        _, bm = load_models()
    except RuntimeError:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    if bm is None:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    expected = behavior_meta.get("expected_features", [
        "time_anomaly", "device_anomaly", "location_anomaly", "action_entropy", "ip_risk", "session_duration"
    ])
    try:
        _assert_schema(6, {"expected_features": expected})
        feats = _ordered_feature_row([t, d, l, e, ip, dur], expected)
        return _predict_prob(bm, feats)
    except Exception as e:
        logger.exception("Behavior model inference failed, fallback to rule: %s", e)
        return _rule_behavior(session)


# ---------------- Rule-based fallbacks ----------------
def _rule_risk(face_match: float, fingerprint_verified: float,
               behavior_anomaly: float, keystroke_anomaly: float) -> float:
    """
    Simple weighted rule:
      - lower face_match => higher risk
      - unverified fp => higher risk
      - higher behavior/keystroke anomalies => higher risk
    """
    return float(np.clip(
        0.30 * (1.0 - face_match) +
        0.25 * (1.0 - float(fingerprint_verified)) +
        0.25 * behavior_anomaly +
        0.20 * keystroke_anomaly,
        0.0, 1.0
    ))


def _rule_behavior(session) -> float:
    t = _safe01(getattr(session, 'time_anomaly', 0.0), 0.0)        # 0..1
    d = _safe01(getattr(session, 'device_anomaly', 0.0), 0.0)      # 0/1
    l = _safe01(getattr(session, 'location_anomaly', 0.0), 0.0)    # 0..1
    # >>> DO NOT change addresses of models (respected) <<<
    return float(np.clip(0.3 * t + 0.4 * d + 0.3 * l, 0.0, 1.0))
