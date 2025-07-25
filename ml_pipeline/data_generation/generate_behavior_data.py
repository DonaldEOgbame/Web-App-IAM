#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate a **non‑leaky** synthetic dataset for the behavior model.

Columns:
- FEATURES (what we serve & train on):
    time_anomaly, device_anomaly, location_anomaly,
    action_entropy, ip_risk, session_duration
- TARGET:
    behavior_anomaly_score (regression target in [0, 1])

Usage:
    python ml_pipeline/data_generation/generate_behavior_data.py \
        --n_rows 1_000_000 \
        --out data/synthetic_behavior_data.parquet
"""
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

FEATURES = [
    "time_anomaly", "device_anomaly", "location_anomaly",
    "action_entropy", "ip_risk", "session_duration"
]
TARGET = "behavior_anomaly_score"


def make_data(n_rows: int, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    time_anomaly = rng.uniform(0, 1, n_rows)  # already normalized 0..1
    device_anomaly = rng.binomial(1, 0.15, n_rows).astype(float)
    location_anomaly = rng.beta(2, 6, n_rows)  # most often low
    action_entropy = rng.beta(3, 3, n_rows)    # centered
    ip_risk = rng.beta(2, 8, n_rows)
    session_duration = rng.gamma(shape=2.0, scale=180.0, size=n_rows)  # ~ minutes * 60

    # True function (nonlinear) + noise
    score = (
        0.35 * device_anomaly
        + 0.25 * location_anomaly
        + 0.15 * ip_risk
        + 0.15 * time_anomaly
        + 0.10 * (action_entropy ** 2)
        + 0.05 * np.log1p(session_duration) / np.log(1 + 3600)
    )

    # Add noise and clamp to [0, 1]
    noise = rng.normal(0, 0.05, n_rows)
    score = np.clip(score + noise, 0.0, 1.0)

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
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    df = make_data(args.n_rows, args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".parquet":
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False)

    print(f"Wrote {len(df):,} rows to {out_path}")


if __name__ == "__main__":
    main()
