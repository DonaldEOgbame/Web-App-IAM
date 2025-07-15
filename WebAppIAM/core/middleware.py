from django.contrib.auth import logout
from django.utils import timezone
from django.shortcuts import redirect
from django.conf import settings
import datetime
import hashlib

class SessionSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_time = timezone.now()
            last_activity = request.session.get('last_activity')
            
            # Default timeout of 30 minutes (1800 seconds)
            timeout_seconds = getattr(settings, 'SESSION_TIMEOUT_SECONDS', 1800)
            
            # Check session timeout
            if last_activity:
                last_activity = datetime.datetime.fromisoformat(last_activity)
                last_activity = last_activity.replace(tzinfo=timezone.utc)
                
                # If the user has been inactive for too long, log them out
                if (current_time - last_activity).total_seconds() > timeout_seconds:
                    logout(request)
                    return redirect('core:login')
            
            # Update the last activity time
            request.session['last_activity'] = current_time.isoformat()
            
            # Session hijacking prevention
            # Generate a fingerprint of the user's request properties
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip_address = request.META.get('REMOTE_ADDR', '')
            
            # Combine characteristics to create a session fingerprint
            fingerprint = hashlib.md5(f"{user_agent}|{ip_address}".encode()).hexdigest()
            
            # If this is a new session, store the fingerprint
            if not request.session.get('security_fingerprint'):
                request.session['security_fingerprint'] = fingerprint
            
            # If the fingerprint has changed significantly, this could be a hijacked session
            elif request.session.get('security_fingerprint') != fingerprint:
                # For strict security, log the user out
                if getattr(settings, 'STRICT_SESSION_SECURITY', True):
                    logout(request)
                    return redirect('core:login')
        
        response = self.get_response(request)
        return response

class ContentSecurityPolicyMiddleware:
    """
    Middleware to add Content Security Policy headers to responses.
    This helps protect against XSS attacks.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Skip API and static file requests
        if not request.path.startswith('/api/') and not request.path.startswith('/static/'):
            # Set CSP headers
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline'",  # Allow inline scripts for now
                "style-src 'self' 'unsafe-inline'",   # Allow inline styles for now
                "img-src 'self' data:",               # Allow data: URLs for images
                "font-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'none'",             # Prevent clickjacking
                "base-uri 'self'",
                "form-action 'self'"
            ]
            
            response['Content-Security-Policy'] = '; '.join(csp_directives)
            
            # Additional security headers
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Referrer-Policy'] = 'same-origin'
            
        return response
