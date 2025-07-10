from django.conf import settings

def calculate_risk_score(face_match_score, fingerprint_verified, behavior_anomaly_score):
    """
    Calculate a comprehensive risk score based on multiple factors.
    
    Args:
        face_match_score (float): Confidence score from face verification (0-1)
        fingerprint_verified (bool): Whether fingerprint was verified
        behavior_anomaly_score (float): Anomaly score from behavior analysis (0-1)
    
    Returns:
        float: Composite risk score (0-1 where 0 is low risk, 1 is high risk)
    """
    # Get weights from settings or use defaults
    face_weight = getattr(settings, 'RISK_FACE_WEIGHT', 0.4)
    fingerprint_weight = getattr(settings, 'RISK_FINGERPRINT_WEIGHT', 0.4)
    behavior_weight = getattr(settings, 'RISK_BEHAVIOR_WEIGHT', 0.2)
    
    # Normalize face component (lower score = higher risk)
    face_risk = 1 - (face_match_score or 0)
    
    # Fingerprint component (not verified = high risk)
    fingerprint_risk = 0 if fingerprint_verified else 1
    
    # Behavior component (direct mapping)
    behavior_risk = behavior_anomaly_score or 0
    
    # Calculate weighted risk score
    weighted_risk = (
        (face_risk * face_weight) +
        (fingerprint_risk * fingerprint_weight) +
        (behavior_risk * behavior_weight)
    )
    
    # Ensure the score is between 0 and 1
    return max(0, min(1, weighted_risk))