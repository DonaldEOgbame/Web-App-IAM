import os
import joblib
import numpy as np
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Configure paths - now pointing to PRODUCTION models
ML_MODELS_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), 
    '../../../ml_pipeline/models/production'
))

# Initialize models as None for lazy loading
risk_model = None
behavior_model = None

def load_models():
    """Lazy-load models on first use with error handling"""
    global risk_model, behavior_model
    
    if not risk_model:
        try:
            risk_path = os.path.join(ML_MODELS_DIR, 'risk_model.pkl')
            risk_model = joblib.load(risk_path)
            logger.info(f"Loaded risk model from {risk_path}")
        except Exception as e:
            logger.error(f"Risk model loading failed: {str(e)}")
            raise RuntimeError("Risk model unavailable - contact administrator")

    if not behavior_model:
        try:
            behavior_path = os.path.join(ML_MODELS_DIR, 'behavior_model.pkl')
            behavior_model = joblib.load(behavior_path)
            logger.info(f"Loaded behavior model from {behavior_path}")
        except Exception as e:
            logger.error(f"Behavior model loading failed: {str(e)}")
            raise RuntimeError("Behavior model unavailable - contact administrator")
    
    return risk_model, behavior_model

def calculate_risk_score(face_match, fingerprint_verified, behavior_anomaly):
    """Calculate risk score using production ML model"""
    load_models()  # Ensure models are loaded
    
    # Create feature vector
    features = np.array([[face_match, fingerprint_verified, behavior_anomaly]])
    
    # Handle model versioning differences
    try:
        return float(risk_model.predict(features)[0])
    except AttributeError:
        # Fallback for older model versions
        return float(risk_model.predict_proba(features)[0][1])

def analyze_behavior_anomaly(session):
    """Analyze behavior anomaly using production ML model"""
    load_models()  # Ensure models are loaded
    
    # Extract features from session object
    features = np.array([[
        getattr(session, 'time_anomaly', 0),
        getattr(session, 'device_anomaly', 0),
        getattr(session, 'location_anomaly', 0),
        getattr(session, 'action_entropy', 0.5),
        getattr(session, 'ip_risk', 0.1),
        getattr(session, 'session_duration', 300)
    ]])
    
    # Handle different model interfaces
    try:
        return float(behavior_model.predict(features)[0])
    except Exception as e:
        logger.warning(f"Behavior prediction exception: {str(e)}")
        # Fallback to rule-based if model fails
        return min(1.0, max(0.0, 
            (session.time_anomaly / 1440 * 0.3) + 
            (session.device_anomaly * 0.4) + 
            (session.location_anomaly * 0.3)
        ))