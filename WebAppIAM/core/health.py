import logging
import time
import json
from django.conf import settings
from django.db import connections
from django.db.utils import OperationalError
from django.http import JsonResponse

from .face_api import check_face_api_status

logger = logging.getLogger(__name__)

def check_database():
    """Check if the database is accessible"""
    try:
        conn = connections['default']
        conn.cursor()
        return True
    except OperationalError:
        return False

def check_services():
    """Check all external service dependencies"""
    services = {
        "database": {
            "status": "operational" if check_database() else "down",
            "required": True
        },
        "face_api": {
            "status": "operational" if check_face_api_status() else "degraded",
            "required": settings.FACE_API_ENABLED
        },
        # Add other services here as needed
    }
    
    # Calculate overall status
    operational = all(svc["status"] == "operational" or not svc["required"] for svc in services.values())
    
    return {
        "status": "operational" if operational else "degraded",
        "services": services,
        "timestamp": time.time()
    }

def health_check(request):
    """Health check endpoint handler"""
    start_time = time.time()
    status = check_services()
    status["response_time_ms"] = int((time.time() - start_time) * 1000)
    
    http_status = 200 if status["status"] == "operational" else 503
    
    # Log health issues if any
    if status["status"] != "operational":
        logger.warning(f"Health check failed: {json.dumps(status)}")
    
    return JsonResponse(status, status=http_status)
