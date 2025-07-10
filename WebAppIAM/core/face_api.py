import os
import requests
from django.conf import settings
from azure.cognitiveservices.vision.face import FaceClient
from msrest.authentication import CognitiveServicesCredentials

def get_face_client():
    face_key = settings.AZURE_FACE_API_KEY
    face_endpoint = settings.AZURE_FACE_API_ENDPOINT
    credentials = CognitiveServicesCredentials(face_key)
    return FaceClient(face_endpoint, credentials)

def enroll_face(user, face_image):
    face_client = get_face_client()
    
    # Create a person group if it doesn't exist
    person_group_id = settings.AZURE_FACE_PERSON_GROUP_ID
    try:
        face_client.person_group.get(person_group_id)
    except:
        face_client.person_group.create(person_group_id, person_group_id)
    
    # Create a person for this user
    person = face_client.person_group_person.create(person_group_id, str(user.id))
    
    # Detect faces in the image
    detected_faces = face_client.face.detect_with_stream(face_image)
    if not detected_faces:
        raise ValueError("No faces detected in the image")
    
    # Add face to the person
    face_client.person_group_person.add_face_from_stream(
        person_group_id, person.person_id, face_image
    )
    
    # Train the person group
    face_client.person_group.train(person_group_id)
    
    return person.person_id

def verify_face(user, face_image):
    face_client = get_face_client()
    person_group_id = settings.AZURE_FACE_PERSON_GROUP_ID
    
    # Detect faces in the image
    detected_faces = face_client.face.detect_with_stream(face_image)
    if not detected_faces:
        raise ValueError("No faces detected in the image")
    
    # Verify against the enrolled face
    verification_result = face_client.face.verify_face_to_person(
        face_id=detected_faces[0].face_id,
        person_id=user.azure_face_id,
        person_group_id=person_group_id
    )
    
    return {
        'is_identical': verification_result.is_identical,
        'confidence': verification_result.confidence
    }