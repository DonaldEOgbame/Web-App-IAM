#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------- Windows / OpenMP stability (must be set before sklearn imports)
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import argparse
import json
import time
import warnings
from pathlib import Path
from typing import List, Optional

import numpy as np
import pandas as pd

from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import KFold, RandomizedSearchCV
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.utils import check_random_state
from sklearn.inspection import permutation_importance
from joblib import dump

# >>> import the calibration wrapper from a real module (pickle-safe)
from ml_pipeline.common.calibration import CalibratedRegressor

warnings.filterwarnings("ignore", category=UserWarning)

# ---- Exact, ordered features also used in production
BEHAVIOR_FEATURES: List[str] = [
    "time_anomaly", "device_anomaly", "location_anomaly",
    "action_entropy", "ip_risk", "session_duration"
]
TARGET = "behavior_anomaly_score"


def save_meta(save_dir: Path, n_train: int, n_test: int, random_state: int,
              calibrated: bool, calib_info: Optional[dict] = None):
    meta = {
        "version": time.strftime("%Y%m%d_%H%M%S"),
        "task": "regression",
        "expected_features": BEHAVIOR_FEATURES,
        "thresholds": {},
        "random_state": random_state,
        "train_rows": int(n_train),
        "test_rows": int(n_test),
        "calibration": {
            "applied": bool(calibrated),
            "method": "isotonic_holdout" if calibrated else None,
            "holdout_frac": calib_info.get("holdout_frac") if calib_info else None
        }
    }
    (save_dir / "behavior_model_meta.json").write_text(json.dumps(meta, indent=2))


def rmse(y_true, y_pred):
    return float(np.sqrt(mean_squared_error(y_true, y_pred)))


def metrics_dict(y_true, y_pred, prefix=""):
    y_pred_c = np.clip(y_pred, 0.0, 1.0)
    return {
        f"{prefix}MAE": float(mean_absolute_error(y_true, y_pred_c)),
        f"{prefix}RMSE": rmse(y_true, y_pred_c),
        f"{prefix}R2": float(r2_score(y_true, y_pred_c)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--test_size", type=float, default=0.2)
    ap.add_argument("--n_splits", type=int, default=3)  # fast
    ap.add_argument("--n_iter", type=int, default=15)   # fast
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument("--save_dir", default="ml_pipeline/models/production")
    ap.add_argument("--calibrate", default="true",
                    help="true/false: apply isotonic calibration on a small holdout")
    ap.add_argument("--save_feature_importance", default="true",
                    help="true/false: save permutation feature importance")
    args = ap.parse_args()

    def _bool_arg(v: str) -> bool:
        return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}

    do_calibrate = _bool_arg(args.calibrate)
    do_importance = _bool_arg(args.save_feature_importance)

    rng = check_random_state(args.random_state)
    save_dir = Path(args.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    # ---- Load
    if args.data.endswith(".parquet"):
        df = pd.read_parquet(args.data)
    else:
        df = pd.read_csv(args.data)

    assert args.target in df.columns, f"{args.target} missing"
    for f in BEHAVIOR_FEATURES:
        if f not in df.columns:
            raise ValueError(f"Missing feature: {f}")

    X_full = df[BEHAVIOR_FEATURES].astype(float)
    y_full = df[args.target].astype(float).clip(0.0, 1.0)

    # ---- Simple random split
    idx = np.arange(len(df))
    rng.shuffle(idx)
    n_test = int(len(df) * args.test_size)
    test_idx = idx[-n_test:]
    train_idx = idx[:-n_test]

    X_train, y_train = X_full.iloc[train_idx], y_full.iloc[train_idx]
    X_test, y_test = X_full.iloc[test_idx], y_full.iloc[test_idx]

    # ---- Pipeline
    base_pipe = Pipeline([
        ("imp", SimpleImputer(strategy="median")),
        ("model", HistGradientBoostingRegressor(
            random_state=args.random_state,
            early_stopping=True
        ))
    ])

    param_dist = {
        "model__learning_rate": np.logspace(-2.5, -0.5, 8),
        "model__max_depth": [None, 3, 5, 7],
        "model__max_leaf_nodes": [15, 31, 63, 127],
        "model__min_samples_leaf": [10, 20, 50, 100],
        "model__l2_regularization": np.logspace(-6, 1, 8),
    }

    cv = KFold(n_splits=args.n_splits, shuffle=True, random_state=args.random_state)
    search = RandomizedSearchCV(
        base_pipe,
        param_distributions=param_dist,
        n_iter=args.n_iter,
        cv=cv,
        scoring="neg_mean_absolute_error",
        n_jobs=1,
        pre_dispatch=1,
        random_state=args.random_state,
        verbose=2
    )
    search.fit(X_train, y_train)
    best = search.best_estimator_

    # ---- Final model (+ optional isotonic output calibration)
    calib_info = {"holdout_frac": 0.1} if do_calibrate else None
    if do_calibrate:
        model = CalibratedRegressor(best, holdout_frac=0.10, random_state=args.random_state)
        model.fit(X_train, y_train)
    else:
        best.fit(X_train, y_train)
        model = best

    # ---- Evaluate
    y_pred = model.predict(X_test)
    report = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "features": BEHAVIOR_FEATURES,
        "cv": {
            "best_params": search.best_params_,
            "best_cv_mae": float(-search.best_score_)
        },
        "test": metrics_dict(y_test, y_pred, prefix="test_"),
        "calibration": {
            "applied": bool(do_calibrate),
            "method": "isotonic_holdout" if do_calibrate else None,
            "holdout_frac": calib_info["holdout_frac"] if calib_info else None
        }
    }
    print(json.dumps(report, indent=2))

    # ---- Save artifacts
    dump(model, save_dir / "behavior_model.pkl")
    save_meta(save_dir, len(X_train), len(X_test), args.random_state,
              calibrated=bool(do_calibrate), calib_info=calib_info)
    (save_dir / "behavior_metrics.json").write_text(json.dumps(report, indent=2))

    # Predictions for sanity checks
    pd.DataFrame({"y_true": y_test, "y_pred": np.clip(y_pred, 0.0, 1.0)}).to_csv(
        save_dir / "behavior_predictions.csv", index=False
    )

    # Optional: permutation importance (works with wrapper because it exposes predict)
    if do_importance:
        try:
            pi = permutation_importance(
                model, X_test, y_test,
                n_repeats=5, random_state=args.random_state, scoring="r2"
            )
            importances = dict(zip(BEHAVIOR_FEATURES, pi.importances_mean.tolist()))
            (save_dir / "behavior_feature_importance.json").write_text(json.dumps(importances, indent=2))
        except Exception as e:
            (save_dir / "behavior_feature_importance.json").write_text(
                json.dumps({"error": f"permutation_importance_failed: {e}"}, indent=2)
            )


if __name__ == "__main__":
    main()
