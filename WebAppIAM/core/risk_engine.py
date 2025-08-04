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
from typing import Optional, Sequence, Tuple
from django.conf import settings
import time

logger = logging.getLogger(__name__)

ML_MODELS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ml_pipeline", "models", "production")
)

# Lazy globals
risk_model: Optional[object] = None
risk_meta: dict = {}
behavior_model: Optional[object] = None
behavior_meta: dict = {}
_loaded = False
_lock = threading.Lock()
_schema_validated = False
_expected_risk_len: Optional[int] = None
_expected_behavior_len: Optional[int] = None

KEYSTROKE_NEUTRAL = 0.5


def _load_models():
    global _loaded, risk_model, risk_meta, behavior_model, behavior_meta
    global _schema_validated, _expected_risk_len, _expected_behavior_len

    if _loaded:
        return
    with _lock:
        if _loaded:
            return

        t0 = time.perf_counter()

        # Load risk model
        try:
            risk_path = os.path.join(ML_MODELS_DIR, "risk_model.pkl")
            risk_meta_path = os.path.join(ML_MODELS_DIR, "risk_model_meta.json")
            if not os.path.exists(risk_path):
                raise FileNotFoundError(f"Risk model file not found: {risk_path}")
            if not os.path.exists(risk_meta_path):
                raise FileNotFoundError(f"Risk model meta file not found: {risk_meta_path}")

            risk_model = joblib.load(risk_path, mmap_mode="r")
            with open(risk_meta_path, "r") as f:
                risk_meta = json.load(f)
            _expected_risk_len = len(risk_meta.get("expected_features", [])) or 4
            logger.info("Loaded risk model v%s", risk_meta.get("version"))
        except Exception as e:
            logger.error("Risk model loading failed: %s", e)
            risk_model, risk_meta = None, {}
            _expected_risk_len = None

        # Load behavior model
        try:
            behavior_path = os.path.join(ML_MODELS_DIR, "behavior_model.pkl")
            behavior_meta_path = os.path.join(ML_MODELS_DIR, "behavior_model_meta.json")
            if not os.path.exists(behavior_path):
                raise FileNotFoundError(f"Behavior model file not found: {behavior_path}")
            if not os.path.exists(behavior_meta_path):
                raise FileNotFoundError(f"Behavior model meta file not found: {behavior_meta_path}")

            behavior_model = joblib.load(behavior_path, mmap_mode="r")
            with open(behavior_meta_path, "r") as f:
                behavior_meta = json.load(f)
            _expected_behavior_len = len(behavior_meta.get("expected_features", [])) or 6
            logger.info("Loaded behavior model v%s", behavior_meta.get("version"))
        except Exception as e:
            logger.error("Behavior model loading failed: %s", e)
            behavior_model, behavior_meta = None, {}
            _expected_behavior_len = None

        # Validate schema once if both metas present
        if risk_model is not None and behavior_model is not None and _expected_risk_len and _expected_behavior_len:
            try:
                _assert_schema(_expected_risk_len, {"expected_features": risk_meta.get("expected_features", [])})
                _assert_schema(_expected_behavior_len, {"expected_features": behavior_meta.get("expected_features", [])})
                _schema_validated = True
            except Exception as e:
                logger.warning("Schema validation during load failed: %s", e)

        _loaded = True
        t1 = time.perf_counter()
        logger.info("ML models load finished in %.3f s", t1 - t0)


def load_models() -> Tuple[object, object]:
    _load_models()
    if risk_model is None or behavior_model is None:
        raise RuntimeError("ML models not loaded")
    return risk_model, behavior_model


def warmup():
    _load_models()
    rf = risk_meta.get("expected_features", ["face_match", "fingerprint_verified", "behavior_anomaly", "keystroke_anomaly"])
    bf = behavior_meta.get("expected_features", [
        "time_anomaly", "device_anomaly", "location_anomaly", "action_entropy", "ip_risk", "session_duration"
    ])
    try:
        if risk_model is not None:
            dummy_risk = _ordered_feature_row([0.0, 1.0, 0.5, KEYSTROKE_NEUTRAL], rf)
            _ = _predict_prob(risk_model, dummy_risk)
        if behavior_model is not None:
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
    n = len(expected_names)
    arr = np.asarray(values, dtype=np.float32).reshape(1, -1)
    if arr.shape[1] < n:
        pad = np.zeros((1, n - arr.shape[1]), dtype=np.float32)
        arr = np.concatenate([arr, pad], axis=1)
    elif arr.shape[1] > n:
        arr = arr[:, :n]
    return arr


def _predict_prob(model, X: np.ndarray) -> float:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        return float(proba[0, 1])
    pred = model.predict(X)
    return float(np.clip(pred[0], 0.0, 1.0))


def calculate_risk_score(face_match: float,
                         fingerprint_verified: bool,
                         behavior_anomaly: float,
                         keystroke_anomaly: Optional[float] = None) -> float:
    fm = _safe01(face_match, 0.0)
    fp = float(bool(fingerprint_verified))
    ba = _safe01(behavior_anomaly, 0.5)
    ka = _safe01(keystroke_anomaly, KEYSTROKE_NEUTRAL)

    try:
        rm, _ = load_models()
    except RuntimeError:
        logger.warning("Risk model unavailable, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    if rm is None or _expected_risk_len is None:
        logger.warning("Risk model metadata missing, falling back to rule-based score.")
        return _rule_risk(fm, fp, ba, ka)

    expected = risk_meta.get("expected_features", ["face_match", "fingerprint_verified", "behavior_anomaly", "keystroke_anomaly"])
    try:
        if not _schema_validated:
            _assert_schema(len(expected), {"expected_features": expected})
        feats = _ordered_feature_row([fm, fp, ba, ka], expected)
        return _predict_prob(rm, feats)
    except Exception as e:
        logger.exception("Risk model inference failed, fallback to rule: %s", e)
        return _rule_risk(fm, fp, ba, ka)


def analyze_behavior_anomaly(session) -> float:
    t = _safe01(getattr(session, 'time_anomaly', 0.0), 0.0)
    d = _safe01(getattr(session, 'device_anomaly', 0.0), 0.0)
    l = _safe01(getattr(session, 'location_anomaly', 0.0), 0.0)
    e = _safe01(getattr(session, 'action_entropy', 0.5), 0.5)
    ip = _safe01(getattr(session, 'ip_risk', 0.1), 0.1)
    dur = float(getattr(session, 'session_duration', 300.0))

    try:
        _, bm = load_models()
    except RuntimeError:
        logger.warning("Behavior model unavailable, using rule fallback.")
        return _rule_behavior(session)

    if bm is None or _expected_behavior_len is None:
        logger.warning("Behavior model metadata missing, using rule fallback.")
        return _rule_behavior(session)

    expected = behavior_meta.get("expected_features", [
        "time_anomaly", "device_anomaly", "location_anomaly", "action_entropy", "ip_risk", "session_duration"
    ])
    try:
        if not _schema_validated:
            _assert_schema(len(expected), {"expected_features": expected})
        feats = _ordered_feature_row([t, d, l, e, ip, dur], expected)
        return _predict_prob(bm, feats)
    except Exception as e:
        logger.exception("Behavior model inference failed, fallback to rule: %s", e)
        return _rule_behavior(session)


def _rule_risk(face_match: float, fingerprint_verified: float,
               behavior_anomaly: float, keystroke_anomaly: float) -> float:
    return float(np.clip(
        0.30 * (1.0 - face_match) +
        0.25 * (1.0 - float(fingerprint_verified)) +
        0.25 * behavior_anomaly +
        0.20 * keystroke_anomaly,
        0.0, 1.0
    ))


def _rule_behavior(session) -> float:
    t = _safe01(getattr(session, 'time_anomaly', 0.0), 0.0)
    d = _safe01(getattr(session, 'device_anomaly', 0.0), 0.0)
    l = _safe01(getattr(session, 'location_anomaly', 0.0), 0.0)
    return float(np.clip(0.3 * t + 0.4 * d + 0.3 * l, 0.0, 1.0))
