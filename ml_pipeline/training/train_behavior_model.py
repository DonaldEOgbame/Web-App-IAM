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
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.experimental import enable_hist_gradient_boosting  # noqa: F401
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import GroupKFold, KFold, RandomizedSearchCV
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
    return pre, num_cols, cat_cols


def cv_scores(estimator: FitPredictor, X: pd.DataFrame, y: pd.Series, cv, groups=None):
    maes, rmses, r2s = [], [], []
    split_iter = cv.split(X, y, groups) if groups is not None else cv.split(X, y)

    for tr_idx, va_idx in split_iter:
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


def leakage_corr_top(X: pd.DataFrame, y: pd.Series, k: int = 10):
    corrs = {}
    for c in X.columns:
        if pd.api.types.is_numeric_dtype(X[c]):
            try:
                corrs[c] = float(abs(np.corrcoef(X[c].astype(float), y)[0, 1]))
            except Exception:
                pass
    return dict(sorted(corrs.items(), key=lambda kv: kv[1], reverse=True)[:k])


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
    ap.add_argument("--data", required=True, help="Path to synthetic_behavior_data.{parquet,csv}")
    ap.add_argument("--target", default="behavior_anomaly_score")
    ap.add_argument("--user_col", default="user_id")
    ap.add_argument("--test_size", type=float, default=0.2)
    ap.add_argument("--n_splits", type=int, default=5)
    ap.add_argument("--random_state", type=int, default=42)
    ap.add_argument("--drop_formula_features", action="store_true",
                    help="Drop known formula components to reduce leakage.")
    ap.add_argument("--save_dir", default="artifacts_behavior")
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

    y = df[args.target]
    X = df.drop(columns=[args.target])

    # Optional: drop “formula” features (leakage)
    formula_feats = ["time_anomaly", "device_anomaly", "location_anomaly",
                     "action_entropy", "ip_risk"]
    if args.drop_formula_features:
        drop_cols = [c for c in formula_feats if c in X.columns]
        X = X.drop(columns=drop_cols)

    # Group-aware train/test split if user_id present
    if args.user_col in X.columns:
        users = X[args.user_col].unique()
        rng.shuffle(users)
        n_test_users = max(1, int(len(users) * args.test_size))
        test_users = set(users[-n_test_users:])
        test_mask = X[args.user_col].isin(test_users).to_numpy()
        train_mask = ~test_mask

        X_train, y_train = X.loc[train_mask], y.loc[train_mask]
        X_test, y_test = X.loc[test_mask], y.loc[test_mask]

        groups_train = X_train[args.user_col].to_numpy()
        use_groups = True
    else:
        idx = np.arange(len(X))
        rng.shuffle(idx)
        n_test = int(len(X) * args.test_size)
        test_idx = idx[-n_test:]
        train_idx = idx[:-n_test]

        X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
        X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

        groups_train = None
        use_groups = False

    pre, num_cols, cat_cols = build_preprocessor(X_train)

    # Baseline
    baseline = Pipeline([
        ("pre", pre),
        ("lr", LinearRegression())
    ])

    # CV
    if use_groups:
        cv = GroupKFold(n_splits=args.n_splits)
        baseline_cv = cv_scores(baseline, X_train, y_train, cv, groups=groups_train)
        cv_for_search = cv.split(X_train, y_train, groups_train)
    else:
        cv = KFold(n_splits=args.n_splits, shuffle=True, random_state=args.random_state)
        baseline_cv = cv_scores(baseline, X_train, y_train, cv)
        cv_for_search = cv

    # Main model + search
    hgbr = HistGradientBoostingRegressor(random_state=args.random_state, early_stopping=True)
    pipe = Pipeline([
        ("pre", pre),
        ("model", hgbr)
    ])

    param_dist = {
        "model__learning_rate": np.logspace(-2.5, -0.7, 12),
        "model__max_depth": [None, 3, 5, 7, 9],
        "model__max_leaf_nodes": [15, 31, 63, 127, None],
        "model__min_samples_leaf": [10, 20, 50, 100],
        "model__l2_regularization": np.logspace(-6, 1, 8),
    }

    search = RandomizedSearchCV(
        pipe,
        param_distributions=param_dist,
        n_iter=40,
        cv=cv_for_search,
        scoring="neg_mean_absolute_error",
        random_state=args.random_state,
        n_jobs=1,          # serial to avoid Windows crashes
        pre_dispatch=1,
        verbose=2
    )

    search = run_random_search_with_retry(search, X_train, y_train)
    best = cast(Pipeline, search.best_estimator_)

    tuned_cv = {
        "best_params": search.best_params_,
        "best_cv_mae": float(-search.best_score_)
    }

    # Fit & test
    best.fit(X_train, y_train)
    y_pred_test = best.predict(X_test)
    test_metrics = metrics_dict(y_test, y_pred_test, prefix="test_")

    # Baseline test
    baseline.fit(X_train, y_train)
    y_pred_bl = baseline.predict(X_test)
    test_metrics_bl = metrics_dict(y_test, y_pred_bl, prefix="baseline_test_")

    # Permutation importance (safe version: work on transformed matrix)
    try:
        pre_step = best.named_steps["pre"]      # type: ignore[attr-defined]
        model_step = best.named_steps["model"]  # type: ignore[attr-defined]

        X_test_tx = pre_step.transform(X_test)

        try:
            feat_names = pre_step.get_feature_names_out()  # sklearn >= 1.0
        except Exception:
            # Fallback for older sklearn
            num_cols_tx = pre_step.transformers_[0][2]
            cat_cols_tx = pre_step.transformers_[1][2]
            ohe = pre_step.named_transformers_["cat"].named_steps["ohe"]
            feat_names = np.concatenate([num_cols_tx, ohe.get_feature_names_out(cat_cols_tx)])

        perm = permutation_importance(
            model_step, X_test_tx, y_test,
            n_repeats=10, random_state=args.random_state, n_jobs=1
        )

        fi_df = pd.DataFrame({
            "feature": feat_names,
            "importance_mean": perm.importances_mean,
            "importance_std": perm.importances_std
        }).sort_values("importance_mean", ascending=False).head(30)
        fi_df.to_csv(save_dir / "behavior_feature_importance.csv", index=False)
    except Exception as e:
        print("Permutation importance failed:", e)

    # Predictions
    pd.DataFrame({"y_true": y_test, "y_pred": y_pred_test}).to_csv(
        save_dir / "behavior_predictions.csv", index=False
    )

    # Save model
    dump(best, save_dir / "behavior_model.pkl")

    # Metrics + leakage corr
    leak_top = leakage_corr_top(X_train, y_train, k=10)
    report = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "drop_formula_features": bool(args.drop_formula_features),
        "leakage_corr_top10": leak_top,
        "cv": {
            "baseline_linear": baseline_cv,
            "tuned_hgbr": tuned_cv
        },
        "test": {
            **test_metrics,
            **test_metrics_bl
        }
    }
    (save_dir / "behavior_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
