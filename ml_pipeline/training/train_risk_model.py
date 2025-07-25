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
    precision_recall_curve
)
from sklearn.model_selection import KFold, RandomizedSearchCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.utils import check_random_state
from joblib import dump

warnings.filterwarnings("ignore", category=UserWarning)

# ---- Exact, ordered features also used in production
RISK_FEATURES: List[str] = ["face_match", "fingerprint_verified", "behavior_anomaly"]
TARGET = "risk_label"


def save_meta(save_dir: Path, n_train: int, n_test: int, random_state: int,
              low: float, high: float):
    meta = {
        "version": time.strftime("%Y%m%d_%H%M%S"),
        "task": "binary_classification",
        "expected_features": RISK_FEATURES,
        "thresholds": {"low": low, "high": high},
        "random_state": random_state,
        "train_rows": int(n_train),
        "test_rows": int(n_test)
    }
    (save_dir / "risk_model_meta.json").write_text(json.dumps(meta, indent=2))


def find_thresholds(y_true, y_score, low_target_fp_rate=0.02, high_target_fp_rate=0.10):
    """
    Heuristic: choose two probability cutoffs for LOW/MEDIUM/HIGH based on target FP rates.
    You can replace with business-cost curve optimization later.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, y_score)
    # thresholds are len-1 vs precision/recall len, so pad
    thresholds = np.append(thresholds, 1.0)

    # Map FP rate by computing confusion on a grid:
    # For speed we estimate using prevalence & PR curve. You can make it exact if needed.
    # We'll just pick percentiles as a quick heuristic:
    low = float(np.quantile(y_score, 1 - high_target_fp_rate))   # lower barrier
    high = float(np.quantile(y_score, 1 - low_target_fp_rate))   # higher barrier
    low = max(0.0, min(1.0, low))
    high = max(0.0, min(1.0, high))
    if high < low:
        high, low = low, high
    return low, high


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--test_size", type=float, default=0.2)
    ap.add_argument("--n_splits", type=int, default=3)  # fast
    ap.add_argument("--n_iter", type=int, default=15)   # fast
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument("--save_dir", default="ml_pipeline/models/production")
    args = ap.parse_args()

    rng = check_random_state(args.random_state)
    save_dir = Path(args.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    # ---- Load
    if args.data.endswith(".parquet"):
        df = pd.read_parquet(args.data)
    else:
        df = pd.read_csv(args.data)

    assert args.target in df.columns, f"{args.target} missing"
    for f in RISK_FEATURES:
        if f not in df.columns:
            raise ValueError(f"Missing feature: {f}")

    y = df[args.target].astype(int)
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
    pipe = Pipeline([
        ("imp", SimpleImputer(strategy="median")),
        ("model", HistGradientBoostingClassifier(
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
        pipe,
        param_distributions=param_dist,
        n_iter=args.n_iter,
        cv=cv,
        scoring="average_precision",
        n_jobs=1,
        pre_dispatch=1,
        random_state=args.random_state,
        verbose=2
    )
    search.fit(X_train, y_train)
    best = search.best_estimator_

    # ---- Evaluate
    best.fit(X_train, y_train)
    if hasattr(best, "predict_proba"):
        y_score = best.predict_proba(X_test)[:, 1]
    else:
        y_score = best.decision_function(X_test)
        # normalize to [0, 1]
        y_score = (y_score - y_score.min()) / (y_score.max() - y_score.min() + 1e-9)

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
            "best_cv_ap": float(search.best_score_)
        },
        "test": {
            "average_precision": ap_score,
            "roc_auc": roc_score,
            "f1_at_0p5": f1,
            "low_threshold": low_thr,
            "high_threshold": high_thr
        }
    }
    print(json.dumps(report, indent=2))

    # ---- Save artifacts
    dump(best, save_dir / "risk_model.pkl")
    save_meta(save_dir, len(X_train), len(X_test), args.random_state,
              low=low_thr, high=high_thr)
    (save_dir / "risk_metrics.json").write_text(json.dumps(report, indent=2))

    # Save predictions for sanity checks
    pd.DataFrame({"y_true": y_test, "y_score": y_score}).to_csv(
        save_dir / "risk_predictions.csv", index=False
    )


if __name__ == "__main__":
    main()
