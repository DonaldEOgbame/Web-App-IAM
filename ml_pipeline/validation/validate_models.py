import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import precision_recall_curve, auc
import os
import json

def validate_models(
    risk_model_path=None,
    behavior_model_path=None,
    risk_data_path=None,
    behavior_data_path=None,
    output_dir=None,
):
    """Validate trained models using the latest generated datasets."""

    base_dir = os.path.join(os.path.dirname(__file__), "..")

    risk_model_path = risk_model_path or os.path.join(base_dir, "models", "risk_model.pkl")
    behavior_model_path = behavior_model_path or os.path.join(base_dir, "models", "behavior_model.pkl")
    risk_data_path = risk_data_path or os.path.join(base_dir, "data", "synthetic_risk_data.parquet")
    behavior_data_path = behavior_data_path or os.path.join(base_dir, "data", "synthetic_behavior_data.parquet")
    output_dir = output_dir or os.path.join(base_dir, "validation_reports")

    os.makedirs(output_dir, exist_ok=True)
    
    # Load models and data
    risk_model = joblib.load(risk_model_path) if risk_model_path else None
    behavior_model = joblib.load(behavior_model_path) if behavior_model_path else None
    risk_df = pd.read_parquet(risk_data_path)
    
    # Attack scenarios
    scenarios = {
        "Credential Stuffing": {
            "face_match_score": np.random.uniform(0.1, 0.3, 1000),
            "fingerprint_verified": np.zeros(1000),
            "behavior_anomaly_score": np.random.uniform(0.8, 0.95, 1000)
        },
        "Deepfake Injection": {
            "face_match_score": np.random.uniform(0.92, 0.99, 1000),
            "fingerprint_verified": np.ones(1000),
            "behavior_anomaly_score": np.random.uniform(0.7, 0.9, 1000)
        },
        "Insider Threat": {
            "face_match_score": np.random.uniform(0.85, 0.95, 1000),
            "fingerprint_verified": np.ones(1000),
            "behavior_anomaly_score": np.clip(np.random.normal(0.4, 0.2, 1000), 0, 1)
        }
    }
    
    # Validation results
    results = {
        "risk_model_metrics": {},
        "behavior_model_metrics": {},
        "attack_scenarios": {}
    }
    
    if risk_model is not None:
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
            sample_size = min(10000, len(risk_df))
            benign_samples = risk_df.sample(sample_size)
            benign_preds = risk_model.predict(
                benign_samples[['face_match_score', 'fingerprint_verified', 'behavior_anomaly_score']]
            )
            fp_rate = np.mean(benign_preds > high_risk_threshold)

            results["attack_scenarios"][name] = {
                "detection_rate": float(detection_rate),
                "false_positive_rate": float(fp_rate)
            }

    if behavior_model is not None:
        behavior_df = pd.read_parquet(behavior_data_path)

        behavior_features = [
            'time_anomaly',
            'device_anomaly',
            'location_anomaly',
            'action_entropy',
            'ip_risk',
            'session_duration',
        ]

        if {'avg_hold_time', 'avg_flight_time'} <= set(behavior_df.columns):
            behavior_features += ['avg_hold_time', 'avg_flight_time']

        X_behavior = behavior_df[behavior_features]
        y_behavior = behavior_df['behavior_anomaly_score']

        behavior_preds = behavior_model.predict(X_behavior)

        behavior_mae = np.mean(np.abs(behavior_preds - y_behavior))
        results['behavior_model_metrics']['MAE'] = float(behavior_mae)

        if 'is_anomaly' in behavior_df.columns:
            threshold = 0.5
            actual_anomaly = behavior_df['is_anomaly'] == 1
            detection = np.mean(behavior_preds[actual_anomaly] > threshold)
            results['behavior_model_metrics']['attack_detection'] = float(detection)
    
    # Validate with keystroke features if available
    keystroke_path = os.path.join(os.path.dirname(__file__), '../data/keystroke_features.csv')
    if os.path.exists(keystroke_path):
        keystroke_df = pd.read_csv(keystroke_path)
        # Example: join on user/session, or aggregate as needed
        risk_df = pd.merge(risk_df, keystroke_df, how='left', left_on='user_id', right_on='user')
        # Optionally, add validation metrics for keystroke-based detection
    
    # Generate report
    report_path = os.path.join(output_dir, "validation_report.json")
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Validation report saved to {report_path}")
    return results

if __name__ == "__main__":
    validate_models()
