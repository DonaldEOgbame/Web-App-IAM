import pandas as pd
import numpy as np
from xgboost import XGBRegressor
from sklearn.model_selection import TimeSeriesSplit
from skopt import BayesSearchCV
from skopt.space import Real, Integer
import joblib
import shap
import os

def train_risk_model(data_path="../data/synthetic_risk_data.parquet", 
                     output_dir="../models"):
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
    
    # Bayesian optimization
    params = {
        'learning_rate': Real(0.01, 0.3, prior='log-uniform'),
        'max_depth': Integer(3, 12),
        'n_estimators': Integer(100, 1000),
        'reg_alpha': Real(1e-5, 100, prior='log-uniform')
    }
    
    model = XGBRegressor(objective='reg:squarederror', n_jobs=-1)
    opt = BayesSearchCV(model, params, n_iter=50, cv=3, scoring='neg_mean_absolute_error')
    opt.fit(X_train, y_train)
    
    # Evaluate
    best_model = opt.best_estimator_
    test_score = best_model.score(X_test, y_test)
    print(f"Model trained with R²: {test_score:.4f}")
    
    # SHAP analysis
    explainer = shap.Explainer(best_model)
    shap_values = explainer(X_test)
    shap.summary_plot(shap_values, X_test, show=False)
    
    # Save model
    output_path = os.path.join(output_dir, "risk_model.pkl")
    joblib.dump(best_model, output_path)
    print(f"Model saved to {output_path}")
    
    return best_model

if __name__ == "__main__":
    train_risk_model()