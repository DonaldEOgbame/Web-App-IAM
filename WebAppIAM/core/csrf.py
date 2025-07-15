from functools import wraps
import logging
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.conf import settings

logger = logging.getLogger(__name__)

def ensure_csrf(view_func):
    """
    Decorator to ensure API endpoints have CSRF protection.
    This allows CSRF-exempt views to still validate CSRF for non-WebAuthn API calls.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # For GET requests, we can add the CSRF token to the response
        if request.method == 'GET':
            response = view_func(request, *args, **kwargs)
            if isinstance(response, JsonResponse):
                response['X-CSRFToken'] = get_token(request)
            return response
            
        # Skip CSRF checks for specific exempted paths 
        # (WebAuthn endpoints might need CSRF exemption due to the protocol)
        if getattr(settings, 'CSRF_EXEMPT_PATHS', None):
            for path in settings.CSRF_EXEMPT_PATHS:
                if request.path.startswith(path):
                    return view_func(request, *args, **kwargs)

        # For POST/PUT/DELETE, check for CSRF token
        csrf_token = request.META.get('HTTP_X_CSRFTOKEN')
        session_csrf = request.session.get('csrftoken')
        
        if not csrf_token or not session_csrf or csrf_token != session_csrf:
            logger.warning(f"CSRF validation failed for {request.path} from {request.META.get('REMOTE_ADDR')}")
            return JsonResponse({
                'status': 'error', 
                'message': 'CSRF validation failed'
            }, status=403)
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view
