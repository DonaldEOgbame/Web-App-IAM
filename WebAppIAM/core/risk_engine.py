import os
import json
import joblib
import numpy as np
import logging
import threading
from django.conf import settings

logger = logging.getLogger(__name__)

# Path to deployed artifacts
ML_MODELS_DIR = getattr(
    settings,
    "ML_MODELS_DIR",
    os.path.abspath(os.path.join(settings.BASE_DIR, "ml_pipeline", "models", "production"))
)

# Lazy globals
_risk_model = None
_risk_meta = {}
_behavior_model = None
_behavior_meta = {}
_loaded = False
_lock = threading.Lock()


def _load_models():
    global _loaded, _risk_model, _risk_meta, _behavior_model, _behavior_meta
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        try:
            risk_path = os.path.join(ML_MODELS_DIR, "risk_model.pkl")
            risk_meta_path = os.path.join(ML_MODELS_DIR, "risk_model_meta.json")
            _risk_model = joblib.load(risk_path)
            _risk_meta = json.loads(open(risk_meta_path, "r").read())
            logger.info("Loaded risk model v%s", _risk_meta.get("version"))
        except Exception as e:
            logger.error("Risk model loading failed: %s", e)

        try:
            behavior_path = os.path.join(ML_MODELS_DIR, "behavior_model.pkl")
            behavior_meta_path = os.path.join(ML_MODELS_DIR, "behavior_model_meta.json")
            _behavior_model = joblib.load(behavior_path)
            _behavior_meta = json.loads(open(behavior_meta_path, "r").read())
            logger.info("Loaded behavior model v%s", _behavior_meta.get("version"))
        except Exception as e:
            logger.error("Behavior model loading failed: %s", e)

        _loaded = True


def load_models():
    """Public wrapper returning loaded ML models for testing

    Raises
    ------
    RuntimeError
        If either the risk or behavior model failed to load.
    """
    _load_models()

    if _risk_model is None or _behavior_model is None:
        raise RuntimeError("ML models not loaded")

    return _risk_model, _behavior_model


def _assert_schema(n_cols: int, meta: dict):
    expected = meta.get("expected_features", [])
    if not expected:
        logger.warning("No expected_features in model meta; skipping schema check.")
        return
    if n_cols != len(expected):
        raise ValueError(f"Feature count mismatch: got {n_cols}, expected {len(expected)}")


def calculate_risk_score(face_match: float,
                         fingerprint_verified: bool,
                         behavior_anomaly: float) -> float:
    """
    Returns probability-like risk score in [0, 1].
    Falls back to rule-based if model unavailable.
    """
    try:
        risk_model, _ = load_models()
    except RuntimeError:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(face_match, fingerprint_verified, behavior_anomaly)
    feats = np.array([[face_match, float(fingerprint_verified), behavior_anomaly]], dtype=float)

    if risk_model is None:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(face_match, fingerprint_verified, behavior_anomaly)

    try:
        _assert_schema(feats.shape[1], _risk_meta)
        if hasattr(risk_model, "predict_proba"):
            return float(risk_model.predict_proba(feats)[0, 1])
        # Regressor fallback
        return float(np.clip(risk_model.predict(feats)[0], 0.0, 1.0))
    except Exception as e:
        logger.exception("Risk model inference failed, fallback to rule: %s", e)
        return _rule_risk(face_match, fingerprint_verified, behavior_anomaly)


def analyze_behavior_anomaly(session) -> float:
    """
    Returns behavior anomaly score in [0, 1].
    Falls back to rule-based if model unavailable.
    """
    try:
        _, behavior_model = load_models()
    except RuntimeError:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)
    feats = np.array([[
        getattr(session, 'time_anomaly', 0.0),
        getattr(session, 'device_anomaly', 0.0),
        getattr(session, 'location_anomaly', 0.0),
        getattr(session, 'action_entropy', 0.5),
        getattr(session, 'ip_risk', 0.1),
        getattr(session, 'session_duration', 300.0),
    ]], dtype=float)

    if behavior_model is None:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    try:
        _assert_schema(feats.shape[1], _behavior_meta)
        if hasattr(behavior_model, "predict_proba"):
            return float(behavior_model.predict_proba(feats)[0, 1])
        # Regressor fallback
        return float(np.clip(behavior_model.predict(feats)[0], 0.0, 1.0))
    except Exception as e:
        logger.exception("Behavior model inference failed, fallback to rule: %s", e)
        return _rule_behavior(session)


# ---------------- Rule-based fallbacks (keep your existing ones or these) ----------------
def _rule_risk(face_match, fingerprint_verified, behavior_anomaly):
    return float(np.clip(
        0.4 * (1 - face_match) +
        0.3 * (1 - float(fingerprint_verified)) +
        0.3 * behavior_anomaly,
        0.0, 1.0
    ))


def _rule_behavior(session):
    t = float(getattr(session, 'time_anomaly', 0.0))        # assume already 0..1
    d = float(getattr(session, 'device_anomaly', 0.0))      # 0/1
    l = float(getattr(session, 'location_anomaly', 0.0))    # 0..1
    return float(np.clip(0.3 * t + 0.4 * d + 0.3 * l, 0.0, 1.0))