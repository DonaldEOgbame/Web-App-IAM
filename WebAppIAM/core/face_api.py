import os
import logging
import base64
from django.conf import settings
from django.core.cache import cache
import time
from azure.cognitiveservices.vision.face import FaceClient
from msrest.authentication import CognitiveServicesCredentials
from .models import AuditLog

logger = logging.getLogger(__name__)

class FaceAPIError(Exception):
    """Exception raised for errors in the Face API."""
    pass

def get_face_client():
    """Return a FaceClient or raise if settings missing."""
    face_key = settings.AZURE_FACE_API_KEY
    face_endpoint = settings.AZURE_FACE_API_ENDPOINT
    if settings.AZURE_FACE_PERSON_GROUP_ID in (None, "", "your-person-group-id"):
        raise FaceAPIError("AZURE_FACE_PERSON_GROUP_ID is not configured")
    credentials = CognitiveServicesCredentials(face_key)
    return FaceClient(face_endpoint, credentials)

def _record_failure():
    count = cache.get("face_api_failure_count", 0) + 1
    cache.set("face_api_failure_count", count, 300)
    if count >= 3:
        cache.set("face_api_circuit_until", time.time() + 300, 300)


def check_face_api_status():
    """Check if the Face API is available."""
    if not settings.FACE_API_ENABLED:
        return False

    circuit_until = cache.get("face_api_circuit_until")
    if circuit_until and circuit_until > time.time():
        return False

    try:
        client = get_face_client()
        next(client.person_group.list(top=1), None)
        cache.set("face_api_failure_count", 0, 300)
        return True
    except Exception:
        logger.exception("Face API health check failed")
        _record_failure()
        return False

def enroll_face(user, face_image_data):
    """
    Enroll a user's face
    
    Args:
        user: User object
        face_image_data: Image data to enroll
        
    Returns:
        Face ID or raises exception
    """
    # Check if Face API is enabled
    if not bool(settings.FACE_API_ENABLED):
        raise FaceAPIError("Face API is disabled")
    
    # Check API availability
    if not check_face_api_status():
        logger.error("Face API is currently unavailable")
        raise FaceAPIError("Face API is currently unavailable. Please try again later.")
    
    face_client = get_face_client()
    
    # Create a person group if it doesn't exist
    person_group_id = settings.AZURE_FACE_PERSON_GROUP_ID
    try:
        face_client.person_group.get(person_group_id)
    except Exception as e:
        logger.info(f"Creating new person group: {person_group_id}")
        try:
            face_client.person_group.create(person_group_id, person_group_id)
        except Exception as create_error:
            logger.error(f"Failed to create person group: {str(create_error)}")
            raise FaceAPIError(f"Failed to configure face recognition: {str(create_error)}")
    
    # Create a person for this user
    person = face_client.person_group_person.create(person_group_id, str(user.id))
    
    # Detect faces in the image
    face_image_data.seek(0)
    detected_faces = face_client.face.detect_with_stream(
        face_image_data,
        return_face_attributes=["liveness"]
    )
    if not detected_faces:
        raise ValueError("No faces detected in the image")
    if len(detected_faces) > 1:
        raise FaceAPIError("Multiple faces detected. Please use a single face image.")
    liveness = getattr(detected_faces[0].face_attributes, "liveness", None)
    if liveness is not None and liveness < 0.5:
        raise FaceAPIError("Liveness detection failed. Please try again.")

    # Add face to the person
    face_image_data.seek(0)
    face_client.person_group_person.add_face_from_stream(
        person_group_id, person.person_id, face_image_data
    )
    
    # Train the person group
    face_client.person_group.train(person_group_id)
    
    # Log successful enrollment
    logger.info(f"Face enrollment successful for user {user.id}")
    
    # Create audit log
    AuditLog.objects.create(
        user=user,
        action="FACE_ENROLLED",
        details=f"Face successfully enrolled",
        ip_address="System"
    )
    
    return person.person_id

def verify_face(user, face_image_data, use_fallback=True, max_retries=2):
    """
    Verify a user's face against their stored face data
    
    Args:
        user: User object
        face_image_data: Image data to verify
        use_fallback: Whether to fall back to alternative auth if API is down
        max_retries: Maximum number of retry attempts
    
    Returns:
        dict with confidence score or raises exception
    """
    # Check if Face API is enabled
    if not settings.FACE_API_ENABLED:
        if use_fallback:
            logger.warning("Face API is disabled, using fallback authentication")
            return {"confidence": 0.7, "fallback": True}  # Medium confidence when using fallback
        raise FaceAPIError("Face API is disabled")
    
    # Check if API is available
    if not check_face_api_status():
        if use_fallback:
            logger.warning("Face API is unavailable, using fallback authentication")
            AuditLog.objects.create(
                user=user,
                action="FACE_API_UNAVAILABLE",
                details="Face API unavailable during verification, used fallback",
                ip_address="System"
            )
            return {"confidence": 0.6, "fallback": True}  # Lower confidence due to API unavailability
        raise FaceAPIError("Face API is currently unavailable")
    
    face_client = get_face_client()
    person_group_id = settings.AZURE_FACE_PERSON_GROUP_ID
    
    # Validation check
    if not user.azure_face_id:
        logger.error(f"User {user.id} doesn't have an enrolled face")
        if use_fallback:
            return {"confidence": 0.3, "fallback": True}  # Very low confidence
        raise FaceAPIError("User doesn't have an enrolled face")
    
    # Retry loop
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            # Detect faces in the image
            face_image_data.seek(0)
            detected_faces = face_client.face.detect_with_stream(
                face_image_data,
                return_face_attributes=["liveness"]
            )
            if not detected_faces:
                if attempt == max_retries:
                    raise ValueError("No faces detected in the image")
                logger.warning(f"No faces detected in attempt {attempt+1}, retrying...")
                face_image_data.seek(0)
                continue
            if len(detected_faces) > 1:
                raise FaceAPIError("Multiple faces detected")
            live = getattr(detected_faces[0].face_attributes, "liveness", None)
            if live is not None and live < 0.5:
                raise FaceAPIError("Liveness detection failed")
            
            # Verify against the enrolled face
            verification_result = face_client.face.verify_face_to_person(
                face_id=detected_faces[0].face_id,
                person_id=user.azure_face_id,
                person_group_id=person_group_id
            )
            
            # Log successful verification
            logger.info(f"Face verification successful for user {user.id}")
            
            # Add to audit log
            AuditLog.objects.create(
                user=user,
                action="FACE_VERIFIED",
                details=f"Face verification successful (confidence: {verification_result.confidence:.2f})",
                ip_address="System"
            )
            
            return {
                'is_identical': verification_result.is_identical,
                'confidence': verification_result.confidence
            }
            
        except Exception as e:
            last_error = e
            logger.warning(f"Face verification attempt {attempt+1} failed: {str(e)}")
            if attempt < max_retries:
                continue
    
    # All attempts failed
    logger.error(f"Face API error after {max_retries+1} attempts: {str(last_error)}")
    
    # Create audit log for the failure
    AuditLog.objects.create(
        user=user,
        action="FACE_VERIFICATION_FAILED",
        details=f"Face verification failed after {max_retries+1} attempts: {str(last_error)}",
        ip_address="System"
    )
    
    # Use fallback if enabled
    if use_fallback and settings.RISK_ENGINE_BYPASS:
        logger.warning(f"Face API failed, using fallback authentication for user {user.id}")
        return {"confidence": 0.5, "fallback": True}  # Lower confidence when using fallback
        
    raise FaceAPIError(f"Face verification failed: {str(last_error)}")
