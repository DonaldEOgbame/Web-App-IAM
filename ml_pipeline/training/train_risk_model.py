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
from typing import List

import numpy as np
import pandas as pd

from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
    f1_score,
    precision_recall_curve,
)
from sklearn.model_selection import KFold, RandomizedSearchCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.utils import check_random_state
from sklearn.calibration import CalibratedClassifierCV
from sklearn.inspection import permutation_importance
from joblib import dump

warnings.filterwarnings("ignore", category=UserWarning)

# ---- Exact, ordered features also used in production (UPDATED)
RISK_FEATURES: List[str] = [
    "face_match",
    "fingerprint_verified",
    "behavior_anomaly",
    "keystroke_anomaly",
]
TARGET = "risk_label"


def save_meta(
    save_dir: Path,
    n_train: int,
    n_test: int,
    random_state: int,
    low: float,
    high: float,
    calibrated: bool,
    calib_method: str,
):
    meta = {
        "version": time.strftime("%Y%m%d_%H%M%S"),
        "task": "binary_classification",
        "expected_features": RISK_FEATURES,
        "thresholds": {"low": low, "high": high},
        "random_state": random_state,
        "train_rows": int(n_train),
        "test_rows": int(n_test),
        "calibration": {
            "applied": bool(calibrated),
            "method": calib_method if calibrated else None,
        },
    }
    (save_dir / "risk_model_meta.json").write_text(json.dumps(meta, indent=2))


def find_thresholds(
    y_true, y_score, low_target_fp_rate: float = 0.02, high_target_fp_rate: float = 0.10
):
    """
    Heuristic: choose two probability cutoffs for LOW/MEDIUM/HIGH based on target FP rates.
    You can replace with business-cost curve optimization later.
    """
    # Quantile-based heuristic over scores (fast & stable on synthetic data)
    low = float(np.quantile(y_score, 1 - high_target_fp_rate))   # lower barrier
    high = float(np.quantile(y_score, 1 - low_target_fp_rate))   # higher barrier
    low = max(0.0, min(1.0, low))
    high = max(0.0, min(1.0, high))
    if high < low:
        high, low = low, high
    return low, high


def _bool_arg(v: str) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


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
                    help="true/false: apply isotonic calibration with CV")
    ap.add_argument("--save_feature_importance", default="true",
                    help="true/false: save permutation feature importance")
    args = ap.parse_args()

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

    # Ensure all expected features are present. If 'keystroke_anomaly' is missing (older data),
    # create it with neutral value 0.5 so training still runs.
    for f in RISK_FEATURES:
        if f not in df.columns:
            if f == "keystroke_anomaly":
                df[f] = 0.5
            else:
                raise ValueError(f"Missing feature: {f}")

    # Strongly recommend keystroke_anomaly ∈ [0,1]. Clip just in case.
    df["keystroke_anomaly"] = df["keystroke_anomaly"].astype(float).clip(0.0, 1.0)

    y = df[args.target].astype(int)

    # Fill NaNs: for keystroke_anomaly use neutral 0.5 explicitly; others -> median in pipeline
    if df["keystroke_anomaly"].isna().any():
        df.loc[df["keystroke_anomaly"].isna(), "keystroke_anomaly"] = 0.5

    X = df[RISK_FEATURES].astype(float)

    # ---- Simple random split (no group/time here for brevity)
    idx = np.arange(len(df))
    rng.shuffle(idx)
    n_test = int(len(df) * args.test_size)
    test_idx = idx[-n_test:]
    train_idx = idx[:-n_test]

    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

    # ---- Pipeline
    base_pipe = Pipeline([
        ("imp", SimpleImputer(strategy="median")),
        ("model", HistGradientBoostingClassifier(
            random_state=args.random_state,
            early_stopping=True
        )),
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
        scoring="average_precision",
        n_jobs=1,
        pre_dispatch=1,
        random_state=args.random_state,
        verbose=2,
    )
    search.fit(X_train, y_train)
    best = search.best_estimator_

    # ---- Optional: probability calibration (isotonic with internal CV on training folds)
    calibrated = False
    calib_method = None
    if do_calibrate:
        # Handle sklearn API change: estimator (>=1.4) vs base_estimator (<1.4)
        try:
            calib = CalibratedClassifierCV(estimator=best, method="isotonic", cv=3)  # sklearn >= 1.4
        except TypeError:
            calib = CalibratedClassifierCV(base_estimator=best, method="isotonic", cv=3)  # sklearn < 1.4
        calib.fit(X_train, y_train)
        model = calib
        calibrated = True
        calib_method = "isotonic_cv3"
    else:
        best.fit(X_train, y_train)
        model = best

    # ---- Evaluate
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:, 1]
    else:
        # Fallback for non-probabilistic estimators
        y_raw = model.decision_function(X_test)
        y_score = (y_raw - y_raw.min()) / (y_raw.max() - y_raw.min() + 1e-9)

    ap_score = float(average_precision_score(y_test, y_score))
    roc_score = float(roc_auc_score(y_test, y_score))

    # choose thresholds for production mapping (LOW/MEDIUM/HIGH)
    low_thr, high_thr = find_thresholds(y_test, y_score)

    # simple F1 at 0.5 (not necessarily good for imbalance)
    y_hat = (y_score >= 0.5).astype(int)
    f1 = float(f1_score(y_test, y_hat))

    report = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "features": RISK_FEATURES,
        "cv": {
            "best_params": search.best_params_,
            "best_cv_ap": float(search.best_score_),
        },
        "test": {
            "average_precision": ap_score,
            "roc_auc": roc_score,
            "f1_at_0p5": f1,
            "low_threshold": low_thr,
            "high_threshold": high_thr,
        },
        "calibration": {
            "applied": calibrated,
            "method": calib_method,
        },
    }
    print(json.dumps(report, indent=2))

    # ---- Save artifacts
    dump(model, save_dir / "risk_model.pkl")
    save_meta(
        save_dir,
        len(X_train),
        len(X_test),
        args.random_state,
        low=low_thr,
        high=high_thr,
        calibrated=calibrated,
        calib_method=calib_method,
    )
    (save_dir / "risk_metrics.json").write_text(json.dumps(report, indent=2))

    # Save predictions for sanity checks
    pd.DataFrame({"y_true": y_test, "y_score": y_score}).to_csv(
        save_dir / "risk_predictions.csv", index=False
    )

    # Optional: permutation importance on test split (post-fit)
    if do_importance:
        try:
            pi = permutation_importance(
                model, X_test, y_test,
                n_repeats=5, random_state=args.random_state, scoring="roc_auc"
            )
            importances = dict(zip(RISK_FEATURES, pi.importances_mean.tolist()))
            (save_dir / "risk_feature_importance.json").write_text(
                json.dumps(importances, indent=2)
            )
        except Exception as e:
            # Non-fatal
            (save_dir / "risk_feature_importance.json").write_text(
                json.dumps({"error": f"permutation_importance_failed: {e}"}, indent=2)
            )


if __name__ == "__main__":
    main()
