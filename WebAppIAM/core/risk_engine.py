import os
import json
import joblib
import numpy as np
import logging
import threading
from typing import Optional
from django.conf import settings

logger = logging.getLogger(__name__)

# Path to deployed artifacts (robust path resolution)
ML_MODELS_DIR = getattr(
    settings,
    "ML_MODELS_DIR",
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_pipeline", "models", "production")
    ),
)

# Lazy globals (exposed for tests to patch)
risk_model = None
risk_meta = {}
behavior_model = None
behavior_meta = {}
_loaded = False
_lock = threading.Lock()

# Neutral default when keystrokes are unavailable or insufficient
KEYSTROKE_NEUTRAL = 0.5


def _load_models():
    global _loaded, risk_model, risk_meta, behavior_model, behavior_meta
    if _loaded:
        return
    with _lock:
        if _loaded:
            return

        # Risk model
        try:
            risk_path = os.path.join(ML_MODELS_DIR, "risk_model.pkl")
            risk_meta_path = os.path.join(ML_MODELS_DIR, "risk_model_meta.json")
            if not os.path.exists(risk_path):
                logger.error(f"Risk model file not found: {risk_path}")
                raise FileNotFoundError(f"Risk model file not found: {risk_path}")
            if not os.path.exists(risk_meta_path):
                logger.error(f"Risk model meta file not found: {risk_meta_path}")
                raise FileNotFoundError(f"Risk model meta file not found: {risk_meta_path}")
            risk_model = joblib.load(risk_path)
            with open(risk_meta_path, "r") as f:
                risk_meta = json.load(f)
            logger.info("Loaded risk model v%s", risk_meta.get("version"))
        except Exception as e:
            logger.error("Risk model loading failed: %s", e)
            risk_model, risk_meta = None, {}

        # Behavior model
        try:
            behavior_path = os.path.join(ML_MODELS_DIR, "behavior_model.pkl")
            behavior_meta_path = os.path.join(ML_MODELS_DIR, "behavior_model_meta.json")
            if not os.path.exists(behavior_path):
                logger.error(f"Behavior model file not found: {behavior_path}")
                raise FileNotFoundError(f"Behavior model file not found: {behavior_path}")
            if not os.path.exists(behavior_meta_path):
                logger.error(f"Behavior model meta file not found: {behavior_meta_path}")
                raise FileNotFoundError(f"Behavior model meta file not found: {behavior_meta_path}")
            behavior_model = joblib.load(behavior_path)
            with open(behavior_meta_path, "r") as f:
                behavior_meta = json.load(f)
            logger.info("Loaded behavior model v%s", behavior_meta.get("version"))
        except Exception as e:
            logger.error("Behavior model loading failed: %s", e)
            behavior_model, behavior_meta = None, {}

        _loaded = True


def load_models():
    """Public wrapper returning loaded ML models for testing

    Raises
    ------
    RuntimeError
        If either the risk or behavior model failed to load.
    """
    _load_models()
    if risk_model is None or behavior_model is None:
        raise RuntimeError("ML models not loaded")
    return risk_model, behavior_model


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

    try:
        rm, _ = load_models()
    except RuntimeError:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    feats = np.array([[fm, fp, ba, ka]], dtype=float)

    if rm is None:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    try:
        _assert_schema(feats.shape[1], risk_meta)
        if hasattr(rm, "predict_proba"):
            return float(rm.predict_proba(feats)[0, 1])
        # Regressor fallback (shouldn't happen with classifier)
        return float(np.clip(rm.predict(feats)[0], 0.0, 1.0))
    except Exception as e:
        logger.exception("Risk model inference failed, fallback to rule: %s", e)
        return _rule_risk(fm, fp, ba, ka)


def analyze_behavior_anomaly(session) -> float:
    """
    Returns behavior anomaly score in [0, 1].
    Falls back to rule-based if model unavailable.
    """
    # Gather features from the session with safe defaults
    feats = np.array([[
        _safe01(getattr(session, 'time_anomaly', 0.0), 0.0),
        _safe01(getattr(session, 'device_anomaly', 0.0), 0.0),
        _safe01(getattr(session, 'location_anomaly', 0.0), 0.0),
        _safe01(getattr(session, 'action_entropy', 0.5), 0.5),
        _safe01(getattr(session, 'ip_risk', 0.1), 0.1),
        float(getattr(session, 'session_duration', 300.0)),
    ]], dtype=float)

    try:
        _, bm = load_models()
    except RuntimeError:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    if bm is None:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    try:
        _assert_schema(feats.shape[1], behavior_meta)
        if hasattr(bm, "predict_proba"):
            return float(bm.predict_proba(feats)[0, 1])
        # Regressor (expected): clip to [0,1]
        return float(np.clip(bm.predict(feats)[0], 0.0, 1.0))
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
    return float(np.clip(0.3 * t + 0.4 * d + 0.3 * l, 0.0, 1.0))
