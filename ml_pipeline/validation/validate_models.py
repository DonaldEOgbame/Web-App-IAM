import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import precision_recall_curve, auc
import os
import json

def validate_models(risk_model_path="../models/risk_model.pkl",
                    behavior_model_path="../models/behavior_model.pkl",
                    risk_data_path="../data/synthetic_risk_data.parquet",
                    output_dir="../validation_reports"):
    os.makedirs(output_dir, exist_ok=True)
    
    # Load models and data
    risk_model = joblib.load(risk_model_path)
    behavior_model = joblib.load(behavior_model_path)
    risk_df = pd.read_parquet(risk_data_path)
    
    # Attack scenarios
    scenarios = {
        "Credential Stuffing": {
            "face_match": np.random.uniform(0.1, 0.3, 1000),
            "fingerprint": np.zeros(1000),
            "behavior": np.random.uniform(0.8, 0.95, 1000)
        },
        "Deepfake Injection": {
            "face_match": np.random.uniform(0.92, 0.99, 1000),
            "fingerprint": np.ones(1000),
            "behavior": np.random.uniform(0.7, 0.9, 1000)
        },
        "Insider Threat": {
            "face_match": np.random.uniform(0.85, 0.95, 1000),
            "fingerprint": np.ones(1000),
            "behavior": np.clip(np.random.normal(0.4, 0.2, 1000), 0, 1)
        }
    }
    
    # Validation results
    results = {
        "risk_model_metrics": {},
        "behavior_model_metrics": {},
        "attack_scenarios": {}
    }
    
    # Validate risk model
    X_risk = risk_df[['face_match_score', 'fingerprint_verified', 'behavior_anomaly_score']]
    y_risk = risk_df['risk_score']
    risk_preds = risk_model.predict(X_risk)
    
    # Calculate MAE
    risk_mae = np.mean(np.abs(risk_preds - y_risk))
    results["risk_model_metrics"]["MAE"] = float(risk_mae)
    
    # Calculate high-risk recall
    high_risk_threshold = 0.7
    actual_high_risk = y_risk > high_risk_threshold
    predicted_high_risk = risk_preds > high_risk_threshold
    recall = np.sum(actual_high_risk & predicted_high_risk) / np.sum(actual_high_risk)
    results["risk_model_metrics"]["high_risk_recall"] = float(recall)
    
    # Validate attack scenarios
    for name, scenario in scenarios.items():
        X_attack = pd.DataFrame(scenario)
        preds = risk_model.predict(X_attack)
        detection_rate = np.mean(preds > high_risk_threshold)
        
        # False positive rate
        benign_samples = risk_df.sample(10000)
        benign_preds = risk_model.predict(
            benign_samples[['face_match_score', 'fingerprint_verified', 'behavior_anomaly_score']]
        )
        fp_rate = np.mean(benign_preds > high_risk_threshold)
        
        results["attack_scenarios"][name] = {
            "detection_rate": float(detection_rate),
            "false_positive_rate": float(fp_rate)
        }
    
    # Generate report
    report_path = os.path.join(output_dir, "validation_report.json")
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Validation report saved to {report_path}")
    return results

if __name__ == "__main__":
    validate_models()