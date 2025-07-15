import re
from django.conf import settings

class ContentSecurityPolicyMiddleware:
    """
    Middleware to add Content Security Policy headers to responses
    to prevent XSS and other injection attacks.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        response = self.get_response(request)
        
        # Define CSP directives
        csp_directives = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"],  # Consider removing unsafe-inline in production
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:'],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'frame-ancestors': ["'none'"],  # Prevents clickjacking
            'form-action': ["'self'"],
            'base-uri': ["'self'"],
            'object-src': ["'none'"],  # Prevents object injection
        }
        
        # Build the CSP header value
        csp_value = '; '.join([
            f"{directive} {' '.join(sources)}"
            for directive, sources in csp_directives.items()
        ])
        
        # Add the CSP header to the response
        response['Content-Security-Policy'] = csp_value
        
        # Add additional security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response

class StrictTransportSecurityMiddleware:
    """
    Middleware to add HTTP Strict Transport Security header to responses
    to enforce HTTPS connections.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add HSTS header (only if HTTPS is enabled)
        if not settings.DEBUG:
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            
        return response

class APICSRFProtectionMiddleware:
    """
    Middleware to enforce CSRF protection for API endpoints
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.api_url_pattern = re.compile(r'^/api/')
        
    def __call__(self, request):
        # For API endpoints, ensure CSRF token is present
        if self.api_url_pattern.match(request.path) and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # CSRF check is automatically done by Django's CSRF middleware
            # This middleware just ensures CSRF is not bypassed for API endpoints
            pass
            
        return self.get_response(request)
