import pandas as pd
import numpy as np
from xgboost import XGBRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error
import joblib
import shap
import os

def train_behavior_model(data_path="../data/synthetic_behavior_data.parquet",
                         output_dir="../models"):
    os.makedirs(output_dir, exist_ok=True)
    
    # Load data
    df = pd.read_parquet(data_path)
    features = ['time_anomaly', 'device_anomaly', 'location_anomaly', 
               'action_entropy', 'ip_risk', 'session_duration']
    X = df[features]
    y = df['behavior_anomaly_score']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Train model
    model = XGBRegressor(
        n_estimators=500,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    preds = model.predict(X_test)
    mae = mean_absolute_error(y_test, preds)
    print(f"Model trained with MAE: {mae:.4f}")
    
    # SHAP analysis
    explainer = shap.Explainer(model)
    shap_values = explainer(X_test.iloc[:1000])
    shap.summary_plot(shap_values, X_test.iloc[:1000], show=False)
    
    # Save model
    output_path = os.path.join(output_dir, "behavior_model.pkl")
    joblib.dump(model, output_path)
    print(f"Model saved to {output_path}")
    
    return model

if __name__ == "__main__":
    train_behavior_model()