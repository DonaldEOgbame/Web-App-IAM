#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ------------ Windows / OpenMP stability fixes (must be before sklearn imports)
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

from typing import Protocol, Any, Type, cast
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import TimeSeriesSplit, KFold, RandomizedSearchCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.utils import check_random_state
from joblib import dump

# ---- Robust + Pylance-friendly import of TerminatedWorkerError ----
try:  # type: ignore[attr-defined]
    from joblib.externals.loky.process_executor import TerminatedWorkerError as _TerminatedWorkerError  # type: ignore[attr-defined]
    TerminatedWorkerError: Type[BaseException] = _TerminatedWorkerError  # type: ignore[assignment]
except Exception:  # pragma: no cover
    class TerminatedWorkerError(Exception):
        pass


# ----------------------- typing helpers -----------------------
class FitPredictor(Protocol):
    def fit(self, X: Any, y: Any) -> Any: ...
    def predict(self, X: Any) -> Any: ...


# ----------------------- utils -----------------------
def rmse(y_true, y_pred):
    return np.sqrt(mean_squared_error(y_true, y_pred))


def metrics_dict(y_true, y_pred, prefix: str = ""):
    return {
        f"{prefix}MAE": mean_absolute_error(y_true, y_pred),
        f"{prefix}RMSE": rmse(y_true, y_pred),
        f"{prefix}R2": r2_score(y_true, y_pred),
    }


def build_preprocessor(X: pd.DataFrame):
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    cat_cols = [c for c in X.columns if c not in num_cols]

    num_pipe = Pipeline([("imp", SimpleImputer(strategy="median"))])
    cat_pipe = Pipeline([
        ("imp", SimpleImputer(strategy="most_frequent")),
        ("ohe", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    pre = ColumnTransformer([
        ("num", num_pipe, num_cols),
        ("cat", cat_pipe, cat_cols),
    ])
    return pre


def cv_scores(estimator: FitPredictor, X: pd.DataFrame, y: pd.Series, cv):
    maes, rmses, r2s = [], [], []
    for tr_idx, va_idx in cv.split(X):
        Xtr, Xva = X.iloc[tr_idx], X.iloc[va_idx]
        ytr, yva = y.iloc[tr_idx], y.iloc[va_idx]
        estimator.fit(Xtr, ytr)
        pred = estimator.predict(Xva)
        maes.append(mean_absolute_error(yva, pred))
        rmses.append(rmse(yva, pred))
        r2s.append(r2_score(yva, pred))
    return {
        "cv_mae_mean": float(np.mean(maes)),
        "cv_mae_std": float(np.std(maes)),
        "cv_rmse_mean": float(np.mean(rmses)),
        "cv_rmse_std": float(np.std(rmses)),
        "cv_r2_mean": float(np.mean(r2s)),
        "cv_r2_std": float(np.std(r2s)),
    }


def run_random_search_with_retry(search: RandomizedSearchCV, X, y):
    try:
        return search.fit(X, y)
    except TerminatedWorkerError:
        print("Parallel search crashed. Retrying with n_jobs=1, pre_dispatch=1 …")
        search.set_params(n_jobs=1, pre_dispatch=1, verbose=2)
        return search.fit(X, y)


# ----------------------- main -----------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to synthetic_risk_data.{parquet,csv}")
    ap.add_argument("--target", default="risk_score")
    ap.add_argument("--test_size", type=float, default=0.2, help="Tail fraction used for test.")
    ap.add_argument("--n_splits", type=int, default=5)
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument("--save_dir", default="artifacts_risk")
    args = ap.parse_args()

    rng = check_random_state(args.random_state)
    save_dir = Path(args.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    # Load
    if args.data.endswith(".parquet"):
        df = pd.read_parquet(args.data)
    else:
        df = pd.read_csv(args.data)

    assert args.target in df.columns, f"{args.target} not in data"

    # Preserve temporal order → tail is test
    n_test = int(len(df) * args.test_size)
    train_df = df.iloc[:-n_test]
    test_df = df.iloc[-n_test:]

    y_train = train_df[args.target]
    X_train = train_df.drop(columns=[args.target])

    y_test = test_df[args.target]
    X_test = test_df.drop(columns=[args.target])

    # Preprocess
    pre = build_preprocessor(X_train)

    # Baseline
    baseline = Pipeline([
        ("pre", pre),
        ("lr", LinearRegression())
    ])

    # CV
    if len(X_train) >= args.n_splits:
        cv = TimeSeriesSplit(n_splits=args.n_splits)
    else:
        cv = KFold(n_splits=min(3, len(X_train)), shuffle=True, random_state=args.random_state)

    baseline_cv = cv_scores(baseline, X_train, y_train, cv)

    # Main model + search
    gbr = GradientBoostingRegressor(random_state=args.random_state)
    pipe = Pipeline([
        ("pre", pre),
        ("gbr", gbr)
    ])

    param_dist = {
        "gbr__n_estimators": np.arange(100, 1500, 100),
        "gbr__learning_rate": np.logspace(-2.5, -0.3, 20),
        "gbr__max_depth": np.arange(2, 8),
        "gbr__min_samples_leaf": [1, 3, 5, 10, 20, 50],
        "gbr__subsample": [0.6, 0.8, 1.0]
    }

    search = RandomizedSearchCV(
        pipe,
        param_distributions=param_dist,
        n_iter=60,
        cv=cv,
        scoring="neg_mean_absolute_error",
        n_jobs=1,          # serial to avoid Windows crashes
        pre_dispatch=1,
        verbose=2,
        random_state=args.random_state
    )

    search = run_random_search_with_retry(search, X_train, y_train)
    best = cast(Pipeline, search.best_estimator_)

    tuned_cv = {
        "best_params": search.best_params_,
        "best_cv_mae": float(-search.best_score_)
    }

    # Fit on full train, test
    best.fit(X_train, y_train)
    y_pred = best.predict(X_test)
    test_metrics = metrics_dict(y_test, y_pred, prefix="test_")

    # Baseline on test
    baseline.fit(X_train, y_train)
    y_pred_bl = baseline.predict(X_test)
    test_metrics_bl = metrics_dict(y_test, y_pred_bl, prefix="baseline_test_")

    # Save predictions (with residuals)
    preds_df = pd.DataFrame({
        "y_true": y_test,
        "y_pred": y_pred,
        "residual": y_test - y_pred
    })
    preds_df.to_csv(save_dir / "risk_predictions.csv", index=False)

    # Persist
    dump(best, save_dir / "risk_model.pkl")

    report = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "cv": {
            "baseline_linear": baseline_cv,
            "tuned_gbr": tuned_cv
        },
        "test": {
            **test_metrics,
            **test_metrics_bl
        }
    }
    (save_dir / "risk_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
