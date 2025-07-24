import pandas as pd
import numpy as np
from xgboost import XGBRegressor
from sklearn.model_selection import TimeSeriesSplit
from skopt import BayesSearchCV
from skopt.space import Real, Integer
import joblib
import shap
import os

def train_risk_model(data_path=None, output_dir=None):
    base_dir = os.path.join(os.path.dirname(__file__), "..")
    data_path = data_path or os.path.join(base_dir, "data", "synthetic_risk_data.parquet")
    output_dir = output_dir or os.path.join(base_dir, "models")
    os.makedirs(output_dir, exist_ok=True)
    
    # Load data
    df = pd.read_parquet(data_path)
    X = df[['face_match_score', 'fingerprint_verified', 'behavior_anomaly_score']]
    y = df['risk_score']
    
    # Time-based split
    tscv = TimeSeriesSplit(n_splits=5)
    train_indices, test_indices = list(tscv.split(X))[-1]
    X_train, X_test = X.iloc[train_indices], X.iloc[test_indices]
    y_train, y_test = y.iloc[train_indices], y.iloc[test_indices]
    
    # Simple model training to keep runtime reasonable
    best_model = XGBRegressor(
        objective='reg:squarederror',
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        n_jobs=-1,
        reg_alpha=0
    )
    best_model.fit(X_train, y_train)

    # Evaluate
    test_score = best_model.score(X_test, y_test)
    print(f"Model trained with R²: {test_score:.4f}")
    
    # Skip SHAP analysis for faster execution
    
    # Save model
    output_path = os.path.join(output_dir, "risk_model.pkl")
    joblib.dump(best_model, output_path)
    print(f"Model saved to {output_path}")
    
    return best_model

if __name__ == "__main__":
    train_risk_model()
