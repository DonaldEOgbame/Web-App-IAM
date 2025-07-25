#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate a **non‑leaky** synthetic dataset for the risk model.

Columns:
- FEATURES (what we serve & train on):
    face_match, fingerprint_verified, behavior_anomaly
- TARGET:
    risk_label (0/1 classification), plus optional risk_score (for reference)

Usage:
    python ml_pipeline/data_generation/generate_risk_data.py \
        --n_rows 1_000_000 \
        --out data/synthetic_risk_data.parquet
"""
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.utils import check_random_state

FEATURES = ["face_match", "fingerprint_verified", "behavior_anomaly"]
TARGET = "risk_label"


def make_data(n_rows: int, seed: int = 42, pos_rate: float = 0.05) -> pd.DataFrame:
    rng = check_random_state(seed)

    face_match = np.clip(rng.beta(5, 2, n_rows), 0.0, 1.0)
    fingerprint_verified = rng.binomial(1, 0.9, n_rows).astype(float)
    behavior_anomaly = rng.beta(2, 5, n_rows)

    # true risk (latent probability)
    risk_score = (
        0.55 * (1 - face_match)
        + 0.20 * (1 - fingerprint_verified)
        + 0.25 * behavior_anomaly
    )
    risk_score = np.clip(risk_score + rng.normal(0, 0.05, n_rows), 0.0, 1.0)

    # convert to label with approx target prevalence
    # compute dynamic threshold so that label rate ~ pos_rate
    thr = np.quantile(risk_score, 1 - pos_rate)
    risk_label = (risk_score >= thr).astype(int)

    df = pd.DataFrame({
        "face_match": face_match,
        "fingerprint_verified": fingerprint_verified,
        "behavior_anomaly": behavior_anomaly,
        "risk_score": risk_score,
        TARGET: risk_label
    })
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n_rows", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--pos_rate", type=float, default=0.05)
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    df = make_data(args.n_rows, args.seed, args.pos_rate)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == ".parquet":
        df.to_parquet(out_path, index=False)
    else:
        df.to_csv(out_path, index=False)

    print(f"Wrote {len(df):,} rows to {out_path}")


if __name__ == "__main__":
    main()
