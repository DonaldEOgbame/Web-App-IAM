import numpy as np
import pandas as pd
from scipy.stats import beta, skewnorm
import os

def generate_risk_data(samples=500000, output_dir="../data"):
    os.makedirs(output_dir, exist_ok=True)
    
    # Core distributions
    face_dist = 0.7 * beta.rvs(5, 1.5, size=samples) + 0.3 * beta.rvs(1, 5, size=samples)
    fingerprint_dist = np.random.choice([0, 1], p=[0.25, 0.75], size=samples)
    behavior_dist = np.clip(skewnorm.rvs(-8, loc=0.2, scale=0.3, size=samples), 0, 1)
    
    # Create DataFrame
    df = pd.DataFrame({
        'face_match_score': face_dist,
        'fingerprint_verified': fingerprint_dist,
        'behavior_anomaly_score': behavior_dist
    })
    
    # Non-linear risk calculation with interaction effects
    df['risk_score'] = (
        np.sqrt(1 - df['face_match_score']) * 0.4 +
        (1 - df['fingerprint_verified']) * 0.4 +
        df['behavior_anomaly_score'] ** 1.5 * 0.2 +
        ((1 - df['face_match_score']) * df['behavior_anomaly_score']) * 0.3
    ).clip(0, 1)
    
    # Add concept drift simulation
    df.loc[int(samples*0.6):, 'risk_score'] *= 1.2
    df['risk_score'] = df['risk_score'].clip(0, 1)
    
    # Save to Parquet
    output_path = os.path.join(output_dir, "synthetic_risk_data.parquet")
    df.to_parquet(output_path)
    print(f"Generated risk data with {samples} samples at {output_path}")

if __name__ == "__main__":
    generate_risk_data(samples=500000)
