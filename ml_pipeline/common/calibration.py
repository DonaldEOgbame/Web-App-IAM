# ml_pipeline/common/calibration.py
# -*- coding: utf-8 -*-

from typing import Optional
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.utils import check_random_state


class CalibratedRegressor:
    """
    Isotonic calibration wrapper for regressors with .fit/.predict.
    Fits base on a train split, then learns an isotonic mapping on a
    small holdout: iso( base.predict(X_cal) ) ≈ y_cal.

    At inference: y = clip( iso( clip(base.predict(X), 0, 1) ), 0, 1 ).
    """

    def __init__(self, base_estimator, holdout_frac: float = 0.1, random_state: int = 42):
        self.base = base_estimator
        self.holdout_frac = float(holdout_frac)
        self.random_state = int(random_state)
        self.iso_: Optional[IsotonicRegression] = None

    def fit(self, X, y):
        rng = check_random_state(self.random_state)
        n = len(X)
        idx = np.arange(n)
        rng.shuffle(idx)

        n_cal = max(500, int(self.holdout_frac * n))  # ensure enough for iso fit
        cal_idx = idx[:n_cal]
        fit_idx = idx[n_cal:]

        # Work with pandas or numpy inputs
        X_fit = X.iloc[fit_idx] if hasattr(X, "iloc") else X[fit_idx]
        y_fit = y.iloc[fit_idx] if hasattr(y, "iloc") else y[fit_idx]
        X_cal = X.iloc[cal_idx] if hasattr(X, "iloc") else X[cal_idx]
        y_cal = y.iloc[cal_idx] if hasattr(y, "iloc") else y[cal_idx]

        self.base.fit(X_fit, y_fit)

        base_cal = self.base.predict(X_cal)
        base_cal = np.clip(base_cal, 0.0, 1.0)
        y_cal = np.clip(y_cal, 0.0, 1.0)

        self.iso_ = IsotonicRegression(out_of_bounds="clip")
        self.iso_.fit(base_cal, y_cal)
        return self

    def predict(self, X):
        y_hat = self.base.predict(X)
        y_hat = np.clip(y_hat, 0.0, 1.0)
        if self.iso_ is not None:
            y_hat = self.iso_.predict(y_hat)
        return np.clip(y_hat, 0.0, 1.0)
