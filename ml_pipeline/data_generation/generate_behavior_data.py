#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate a **non-leaky**, more realistic synthetic dataset for the behavior model.

Columns:
- FEATURES (served & trained on):
    time_anomaly, device_anomaly, location_anomaly, action_entropy, ip_risk, session_duration
- TARGET:
    behavior_anomaly_score (regression target in [0, 1])

Design notes
------------
- Introduces **correlations** often seen in production:
  * device_anomaly ↔ ip_risk (new devices often appear with riskier networks)
  * time_anomaly ↔ location_anomaly (odd hours coincide with travel/location shifts)
- Adds **light interactions** in the target (e.g., device*ip, time*location) and noise you can tune.
- Session duration is weakly **shorter when anomalies are high**.
- Still **non-leaky**: target is a noisy nonlinear combination of features (no direct reuse).

Usage:
    python ml_pipeline/data_generation/generate_behavior_data.py \
        --n_rows 1000000 \
        --seed 42 \
        --rho_dev_ip 0.45 \
        --rho_loc_time 0.30 \
        --noise_std 0.05 \
        --out data/synthetic_behavior_data.parquet
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = [
    "time_anomaly", "device_anomaly", "location_anomaly",
    "action_entropy", "ip_risk", "session_duration"
]
TARGET = "behavior_anomaly_score"


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


def make_data(n_rows: int,
              seed: int = 42,
              rho_dev_ip: float = 0.45,
              rho_loc_time: float = 0.30,
              noise_std: float = 0.05) -> pd.DataFrame:
    """
    Parameters
    ----------
    n_rows : int
        Number of samples.
    seed : int
        RNG seed.
    rho_dev_ip : float
        Target correlation (Gaussian space) between device_anomaly and ip_risk drivers.
    rho_loc_time : float
        Target correlation (Gaussian space) between location_anomaly and time_anomaly drivers.
    noise_std : float
        Std of additive Gaussian noise on the target before clamping.
    """
    rng = np.random.default_rng(seed)

    # ---- Latent user/context factors (standard normals)
    # These create realistic dependencies among features without leaking labels.
    z_device = rng.normal(size=n_rows)          # device churn propensity
    z_network = rho_dev_ip * z_device + np.sqrt(max(1e-12, 1 - rho_dev_ip**2)) * rng.normal(size=n_rows)
    z_travel = rng.normal(size=n_rows)          # travel propensity / location shifts
    z_time = rho_loc_time * z_travel + np.sqrt(max(1e-12, 1 - rho_loc_time**2)) * rng.normal(size=n_rows)
    z_actions = rng.normal(size=n_rows)         # workflow/behavior variance

    # ---- Map latent factors to observable FEATURES (all in valid ranges)
    # time_anomaly: skewed low, increased by z_time (odd hours)
    base_time = _sigmoid(0.6 * z_time)  # 0..1
    time_anomaly = np.clip(0.1 + 0.7 * base_time + 0.2 * rng.beta(2, 6, n_rows), 0, 1)

    # device_anomaly: Bernoulli with prob from z_device; convert to float 0/1
    p_device = np.clip(_sigmoid(0.8 * z_device - 1.0), 0.02, 0.85)
    device_anomaly = (rng.uniform(0, 1, n_rows) < p_device).astype(float)

    # location_anomaly: mostly low, lifted by travel factor
    loc_base = np.clip(_sigmoid(0.7 * z_travel - 0.5), 0, 1)
    location_anomaly = np.clip(0.15 * rng.beta(2, 6, n_rows) + 0.85 * loc_base, 0, 1)

    # ip_risk: correlated with device anomalies and network factor, but continuous 0..1
    ip_base = _sigmoid(0.9 * z_network - 0.3)
    ip_risk = np.clip(0.25 * rng.beta(2, 8, n_rows) + 0.55 * ip_base + 0.20 * device_anomaly, 0, 1)

    # action_entropy: centered, slightly increases with anomalies (users behave "oddly")
    act_center = 0.5 + 0.15 * (z_actions / 3.0) + 0.10 * (time_anomaly - 0.3) + 0.08 * (location_anomaly - 0.2)
    action_entropy = np.clip(act_center + 0.05 * rng.normal(size=n_rows), 0, 1)

    # session_duration (seconds): gamma-like; shorter when anomalies are high (users bail/are blocked)
    base_duration = rng.gamma(shape=2.0, scale=180.0, size=n_rows)  # mean ~360s
    anomaly_mix = 0.4 * time_anomaly + 0.4 * location_anomaly + 0.2 * ip_risk
    session_duration = np.maximum(30.0, base_duration * (1.0 - 0.35 * anomaly_mix))

    # ---- Target: nonlinear blend + interactions + noise → clamp to [0,1]
    # Weights tuned so most mass stays below ~0.6 but with a healthy tail.
    raw = (
        0.28 * device_anomaly +
        0.22 * location_anomaly +
        0.16 * ip_risk +
        0.14 * time_anomaly +
        0.12 * (action_entropy ** 2) +
        0.08 * (np.log1p(session_duration) / np.log(1 + 3600)) +
        # interactions
        0.08 * (device_anomaly * ip_risk) +
        0.06 * (time_anomaly * location_anomaly)
    )
    score = np.clip(raw + rng.normal(0.0, noise_std, n_rows), 0.0, 1.0)

    df = pd.DataFrame({
        "time_anomaly": time_anomaly,
        "device_anomaly": device_anomaly,
        "location_anomaly": location_anomaly,
        "action_entropy": action_entropy,
        "ip_risk": ip_risk,
        "session_duration": session_duration,
        TARGET: score
    })
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_rows", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--rho_dev_ip", type=float, default=0.45, help="Correlation driver: device ↔ IP risk")
    ap.add_argument("--rho_loc_time", type=float, default=0.30, help="Correlation driver: location ↔ time")
    ap.add_argument("--noise_std", type=float, default=0.05, help="Additive noise on target before clamping")
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    df = make_data(
        n_rows=args.n_rows,
        seed=args.seed,
        rho_dev_ip=args.rho_dev_ip,
        rho_loc_time=args.rho_loc_time,
        noise_std=args.noise_std
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".parquet":
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False)

    print(f"Wrote {len(df):,} rows to {out_path} "
          f"(rho_dev_ip={args.rho_dev_ip:.2f}, rho_loc_time={args.rho_loc_time:.2f}, noise_std={args.noise_std:.3f})")


if __name__ == "__main__":
    main()
