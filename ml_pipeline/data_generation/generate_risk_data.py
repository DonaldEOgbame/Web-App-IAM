#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate a **non-leaky** synthetic dataset for the risk model (WITH keystroke_anomaly).

Columns:
- FEATURES (what we serve & train on):
    face_match, fingerprint_verified, behavior_anomaly, keystroke_anomaly
- TARGET:
    risk_label (0/1 classification), plus risk_score (latent probability, for reference)

Design notes
------------
- `keystroke_anomaly` has a controllable positive correlation with `behavior_anomaly`
  via a simple 2D Gaussian copula, so the model can learn complementary-but-related signals.
- Optional missingness can simulate logins where keystrokes were not captured; these
  rows get a neutral value (0.5) so the model learns to degrade gracefully without leakage.
- Labels are created by thresholding a noisy linear blend of the inputs to hit a target
  prevalence; no target is used when sampling features to avoid leakage.

Usage:
    python ml_pipeline/data_generation/generate_risk_data.py \
        --n_rows 1000000 \
        --out data/synthetic_risk_data.parquet

Key flags:
    --rho_kb 0.35                 # Corr(behavior_anomaly, keystroke_anomaly) in Gaussian copula space
    --keystroke_missing_rate 0.10 # Fraction of rows with no keystrokes (set to neutral 0.5)
    --pos_rate 0.05               # Target positive rate for labels
    --seed 42
"""
import argparse
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from scipy.stats import norm, beta
from sklearn.utils import check_random_state

FEATURES = ["face_match", "fingerprint_verified", "behavior_anomaly", "keystroke_anomaly"]
TARGET = "risk_label"


def _gaussian_copula_pair(n: int, rho: float, rng: np.random.RandomState) -> Tuple[np.ndarray, np.ndarray]:
    """
    Sample two Uniform(0,1) variables with a specified Gaussian copula correlation.
    Returns (u, v) where each ~ Uniform(0,1), Corr(Phi^-1(u), Phi^-1(v)) = rho.
    """
    # Build correlated normals
    z1 = rng.normal(size=n)
    z2 = rng.normal(size=n)
    z_corr = rho * z1 + np.sqrt(max(1e-12, 1 - rho ** 2)) * z2
    u = norm.cdf(z1)
    v = norm.cdf(z_corr)
    return u, v


def make_data(
    n_rows: int,
    seed: int = 42,
    pos_rate: float = 0.05,
    rho_kb: float = 0.35,
    keystroke_missing_rate: float = 0.10,
) -> pd.DataFrame:
    """
    Create synthetic risk data with 4 input features and a binary label.

    Parameters
    ----------
    n_rows : int
        Number of rows.
    seed : int
        RNG seed.
    pos_rate : float
        Desired positive prevalence (approximate).
    rho_kb : float
        Correlation (Gaussian-copula space) between behavior_anomaly and keystroke_anomaly.
        Typical values: 0.2 - 0.5.
    keystroke_missing_rate : float
        Fraction of rows with no keystrokes captured. Those rows get keystroke_anomaly=0.5 (neutral).
    """
    rng = check_random_state(seed)

    # 1) Face match: good similarity generally, independent of anomalies
    #    Higher is better (0..1).
    face_match = np.clip(rng.beta(5, 2, n_rows), 0.0, 1.0)

    # 2) Fingerprint verified: mostly 1s, a few 0s
    fingerprint_verified = rng.binomial(1, 0.90, n_rows).astype(float)

    # 3) Behavior anomaly: mostly small values, long right tail (0..1)
    #    Draw via Beta(2,5) marginal.
    #    We will *pair* it with keystrokes through a copula to achieve correlation.
    #    First, get uniform marginals with correlation in the Gaussian space.
    u_b, u_k = _gaussian_copula_pair(n_rows, rho=rho_kb, rng=rng)

    behavior_anomaly = beta.ppf(u_b, a=2.0, b=5.0)  # skewed toward 0
    # 4) Keystroke anomaly: a bit "tighter" than behavior, but still skewed low
    keystroke_anomaly = beta.ppf(u_k, a=2.5, b=4.5)

    # Optional missingness: simulate sessions without keystrokes (neutral contribution).
    if keystroke_missing_rate > 0:
        missing_mask = rng.rand(n_rows) < keystroke_missing_rate
        keystroke_anomaly = keystroke_anomaly.copy()
        keystroke_anomaly[missing_mask] = 0.5

    # Latent risk score: weighted, noisy blend (no label leakage)
    # Weights sum to 1.0 before noise; tweak to taste.
    risk_score = (
        0.45 * (1.0 - face_match) +          # lower face_match => higher risk
        0.20 * (1.0 - fingerprint_verified) +
        0.20 * behavior_anomaly +
        0.15 * keystroke_anomaly
    )

    # Add small Gaussian noise to avoid hard linear boundaries
    risk_score = np.clip(risk_score + rng.normal(0.0, 0.05, n_rows), 0.0, 1.0)

    # Convert to label targeting approximate prevalence pos_rate
    thr = float(np.quantile(risk_score, 1.0 - pos_rate))
    risk_label = (risk_score >= thr).astype(int)

    df = pd.DataFrame(
        {
            "face_match": face_match,
            "fingerprint_verified": fingerprint_verified,
            "behavior_anomaly": behavior_anomaly,
            "keystroke_anomaly": keystroke_anomaly,
            "risk_score": risk_score,
            TARGET: risk_label,
        }
    )
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_rows", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--pos_rate", type=float, default=0.05)
    ap.add_argument("--rho_kb", type=float, default=0.35, help="Corr(behavior, keystroke) in Gaussian-copula space")
    ap.add_argument("--keystroke_missing_rate", type=float, default=0.10, help="Fraction of rows with no keystrokes")
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    df = make_data(
        n_rows=args.n_rows,
        seed=args.seed,
        pos_rate=args.pos_rate,
        rho_kb=args.rho_kb,
        keystroke_missing_rate=args.keystroke_missing_rate,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".parquet":
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False)

    print(f"Wrote {len(df):,} rows to {out_path}  "
          f"(pos_rate≈{df[TARGET].mean():.3f}, rho_kb={args.rho_kb}, miss={args.keystroke_missing_rate:.2f})")


if __name__ == "__main__":
    main()
