# views.py
import json
import logging
import csv
import hashlib
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_POST
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Q
from django.template.loader import render_to_string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

from .models import (
    User, UserProfile, UserBehaviorProfile, WebAuthnCredential,
    UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog, 
    Notification, DeviceFingerprint
)
from .models_keystroke import KeystrokeDynamics
from .webauthn_utils import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from .face_api import verify_face, enroll_face
from .risk_engine import calculate_risk_score, analyze_behavior_anomaly
from .forms import (
    RegistrationForm, LoginForm, FaceEnrollForm, FingerprintReRegisterForm,
    RiskPolicyForm, ReportSubmissionForm, CustomPasswordChangeForm,
    DocumentUploadForm, ProfileCompletionForm, ProfileUpdateForm, PasswordResetForm, PasswordResetConfirmForm
)

logger = logging.getLogger(__name__)

# --- Encryption Utilities ---
def get_fernet_key(user=None):
    if user:
        # Derive keys from user password (school-friendly)
        password = (user.password + settings.SECRET_KEY).encode()
    else:
        password = settings.SECRET_KEY.encode()
    salt = settings.SECRET_KEY[:16].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(data, user=None):
    f = Fernet(get_fernet_key(user))
    return f.encrypt(data)

def decrypt_file(encrypted_data, user=None):
    f = Fernet(get_fernet_key(user))
    return f.decrypt(encrypted_data)

# --- Utility Functions ---
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

def get_device_info(request):
    """Extract device information from request"""
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Simple device detection
    device_type = 'Desktop'
    browser = 'Unknown'
    os = 'Unknown'
    
    if 'Mobile' in user_agent or 'Android' in user_agent or 'iPhone' in user_agent:
        device_type = 'Mobile'
    elif 'Tablet' in user_agent or 'iPad' in user_agent:
        device_type = 'Tablet'
    
    # Basic browser detection
    if 'Chrome' in user_agent:
        browser = 'Chrome'
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'
    elif 'Edge' in user_agent:
        browser = 'Edge'
    
    # Basic OS detection
    if 'Windows' in user_agent:
        os = 'Windows'
    elif 'Mac' in user_agent:
        os = 'macOS'
    elif 'Linux' in user_agent:
        os = 'Linux'
    elif 'Android' in user_agent:
        os = 'Android'
    elif 'iOS' in user_agent or 'iPhone' in user_agent or 'iPad' in user_agent:
        os = 'iOS'
    
    return {
        'device_type': device_type,
        'browser': browser,
        'os': os,
        'user_agent': user_agent
    }

def rate_limit(request, key_prefix, limit=5, window=60):
    key = f"rate:{key_prefix}:{get_client_ip(request)}"
    count = cache.get(key, 0)
    if count >= limit:
        return False
    cache.set(key, count + 1, timeout=window)
    return True

def notify_admin(subject, context):
    admins = User.objects.filter(role='ADMIN', is_active=True)
    admin_emails = [admin.email for admin in admins if admin.email]
    if admin_emails:
        send_mail(
            subject,
            context,
            settings.DEFAULT_FROM_EMAIL,
            admin_emails,
            fail_silently=True
        )

def create_new_device_notification(user, session, device_info):
    """Create notification for new device login"""
    # Create or update device fingerprint
    import hashlib
    device_hash = hashlib.sha256(
        f"{device_info['user_agent']}{device_info['browser']}{device_info['os']}".encode()
    ).hexdigest()[:32]
    
    device_fp, created = DeviceFingerprint.objects.get_or_create(
        device_id=device_hash,
        defaults={
            'user': user,
            'browser': device_info['browser'],
            'operating_system': device_info['os'],
            'device_type': device_info['device_type'],
            'user_agent': device_info['user_agent'],
            'last_ip': session.ip_address,
            'last_location': session.location
        }
    )
    
    if not created:
        device_fp.update_usage(session.ip_address, session.location)
        # If device exists and is trusted, don't send notification
        if device_fp.is_trusted:
            return
    
    # Create user notification
    device_description = f"{device_info['browser']} on {device_info['os']} ({device_info['device_type']})"
    location = session.location or "Unknown location"
    
    Notification.objects.create(
        user=user,
        message=f'New device login detected: {device_description} from {location}. If this wasn\'t you, please contact security immediately.',
        notification_type='DEVICE',
        action_required=True,
        metadata={
            'device_info': device_info,
            'device_id': device_hash,
            'session_id': session.id,
            'ip_address': session.ip_address,
            'location': location
        }
    )
    
    # Also create admin notification if user preferences allow
    if hasattr(user, 'profile') and user.profile.receive_email_alerts:
        admins = User.objects.filter(role='ADMIN', is_active=True)
        for admin in admins:
            Notification.objects.create(
                user=admin,
                message=f'New device login for user {user.username}: {device_description} from {location}',
                notification_type='DEVICE',
                metadata={
                    'target_user': user.username,
                    'device_info': device_info,
                    'device_id': device_hash,
                    'session_id': session.id,
                    'ip_address': session.ip_address
                }
            )
    
    # Log the new device detection
    AuditLog.objects.create(
        user=user,
        action='DEVICE_NEW',
        details=f'New device login detected: {device_description}',
        ip_address=session.ip_address,
        metadata={
            'device_info': device_info,
            'device_id': device_hash,
            'session_id': session.id
        }
    )

# --- Helper functions ---
def is_admin(user):
    """Check if the user is an administrator"""
    return user.is_staff and user.is_superuser

# --- Security Logging ---
def log_security_event(request, event_type, details, success=False):
    """Log security-related events with detailed context"""
    user = request.user if request.user.is_authenticated else None
    username = user.username if user else request.POST.get('username', 'anonymous')
    
    # Create audit log entry
    AuditLog.objects.create(
        user=user,
        action=f"SECURITY_{event_type}",
        details=details,
        ip_address=get_client_ip(request)
    )
    
    # Log to application logs with additional context
    log_message = f"Security event: {event_type} | User: {username} | IP: {get_client_ip(request)} | Success: {success} | Details: {details}"
    if success:
        logger.info(log_message)
    else:
        logger.warning(log_message)

# --- Account Lifecycle Views ---
@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def admin_register_user(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    email = request.POST.get('email')
    role = request.POST.get('role', 'USER')
    
    if not all([username, password, email]):
        return JsonResponse({'error': 'All fields are required'}, status=400)
    
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    
    user = User.objects.create_user(
        username=username, 
        password=password, 
        email=email,
        role=role, 
        is_active=False
    )
    UserBehaviorProfile.objects.create(user=user)
    
    # Notify admin about pending approval
    notify_admin(
        'New User Registration',
        f'User {username} ({email}) registered and pending approval.'
    )
    
    return JsonResponse({'status': 'success', 'message': 'User created. Pending admin activation.'})

@login_required
@user_passes_test(is_admin)
@require_POST
def activate_user(request, user_id):
    user = get_object_or_404(User, id=user_id, is_active=False)
    user.is_active = True
    user.save()
    
    # Generate verification token and expiration
    token = Fernet.generate_key().decode()
    expiration = timezone.now() + timedelta(hours=24)  # Link expires in 24 hours
    
    # Save token and expiration in the database
    user.email_verification_token = token
    user.email_verification_expiration = expiration
    user.save()
    
    # Send verification email
    verify_url = request.build_absolute_uri(
        reverse('core:verify_email', kwargs={'user_id': user.id, 'token': token})
    )
    
    subject = 'Verify Your Email'
    message = render_to_string('emails/verify_email.html', {
        'user': user,
        'verify_link': verify_url
    })
    plain_message = render_to_string('emails/verify_email.txt', {
        'user': user,
        'verify_link': verify_url
    })
    
    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=message,
        fail_silently=True
    )
    
    return redirect('core:admin_dashboard')

def verify_email(request, user_id, token):
    user = get_object_or_404(User, id=user_id)
    
    # Check token and expiration
    if user.email_verification_token != token or user.email_verification_expiration < timezone.now():
        return render(request, 'core/login.html', {
            'error': 'Email verification link is invalid or has expired.'
        })
    
    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_expiration = None
    user.save()
    
    # Redirect to profile completion
    request.session['complete_profile_user'] = user.id
    return redirect('core:complete_profile')

def complete_profile(request):
    user_id = request.session.get('complete_profile_user')
    if not user_id:
        return redirect('core:login')
    
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        form = ProfileCompletionForm(request.POST)
        if form.is_valid():
            profile = UserProfile.objects.create(
                user=user,
                department=form.cleaned_data['department'],
                position=form.cleaned_data['position']
            )
            # Update user's name fields
            user.first_name = form.cleaned_data['first_name']
            user.last_name = form.cleaned_data['last_name']
            user.save()
            
            request.session['register_biometrics_user'] = user.id
            return redirect('core:register_biometrics')
    else:
        form = ProfileCompletionForm()
    
    return render(request, 'core/register.html', {
        'form': form,
        'user': user,
        'show_profile_completion': True
    })

def register_biometrics(request):
    # This view will now handle both initial enrollment and re-enrollment
    user = request.user if request.user.is_authenticated else None
    if not user and 'pending_user_id' in request.session:
        user = get_object_or_404(User, id=request.session['pending_user_id'])
    
    if not user:
        return redirect('core:login')
    
    if request.method == 'POST':
        # Handle biometric registration (face or fingerprint)
        if 'face_data' in request.FILES:
            face_data = request.FILES['face_data'].read()
            if enroll_face(user, face_data):
                user.has_biometrics = True
                user.save()
                if request.user.is_authenticated:
                    return redirect('core:staff_dashboard' if user.role == 'STAFF' else 'core:admin_dashboard')
                return redirect('core:login')
        
        # Handle WebAuthn registration
        # (existing WebAuthn logic remains the same)
    
    return render(request, 'core/register.html', {
        'enrollment_type': 'biometric',
        'webauthn_options': generate_registration_options(user) if not user.face_data else None
    })

@login_required
def webauthn_registration_options(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    
    user = request.user
    options = generate_registration_options(user)
    request.session['webauthn_registration_challenge'] = options.challenge
    return JsonResponse(options.to_dict())

@login_required
def webauthn_registration_verify(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    
    user = request.user
    data = json.loads(request.body)
    challenge = request.session.get('webauthn_registration_challenge')
    
    try:
        credential = verify_registration_response(user, data, challenge)
        WebAuthnCredential.objects.create(
            user=user,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
        )
        # Fix: Sync enrollment status properly - no need for separate fields
        # The has_biometrics property already checks for WebAuthn credentials
        user.save()
        
        AuditLog.objects.create(
            user=user,
            action='FINGERPRINT_ENROLL',
            details='Fingerprint enrolled',
            ip_address=get_client_ip(request)
        )
        
        # Complete registration if new user
        if 'register_biometrics_user' in request.session:
            del request.session['register_biometrics_user']
            django_login(request, user)  # Replace auth_login
            dashboard_url = 'admin_dashboard' if user.role == 'ADMIN' else 'staff_dashboard'
            return JsonResponse({'status': 'success', 'redirect': reverse(f'core:{dashboard_url}')})
        
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"WebAuthn registration failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

# --- Authentication Views ---
def login(request):
    """User login view with rate limiting and security checks"""
    if request.method == 'POST':
        form = LoginForm(request.POST)
        # --- Keystroke Dynamics: Save if present ---
        keystroke_data = request.POST.get('keystroke_data')
        username = request.POST.get('username')
        user_obj = None
        if username:
            try:
                user_obj = User.objects.get(username=username)
            except User.DoesNotExist:
                user_obj = None
        if keystroke_data and user_obj:
            try:
                KeystrokeDynamics.objects.create(
                    user=user_obj,
                    session_id=request.session.session_key,
                    event_data=json.loads(keystroke_data)
                )
            except Exception as e:
                logger.warning(f"Failed to save keystroke data: {e}")
        # --- End Keystroke Dynamics ---
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            # Get the user object
            try:
                user = User.objects.get(username=username)
                # Check for account lockout
                if user.failed_login_attempts >= settings.MAX_FAILED_LOGINS:
                    if user.last_failed_login and timezone.now() < user.last_failed_login + timezone.timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES):
                        AuditLog.objects.create(
                            user=None,
                            action='LOGIN_FAIL',
                            details=f'Login attempt on locked account: {username}',
                            ip_address=get_client_ip(request)
                        )
                        messages.error(request, f'Account locked due to too many failed attempts. Try again in {settings.ACCOUNT_LOCKOUT_MINUTES} minutes.')
                        return render(request, 'core/login.html', {'form': form})
                    else:
                        # Reset failed attempts after lockout period
                        user.failed_login_attempts = 0
                        user.save(update_fields=['failed_login_attempts'])
                # Authenticate the user
                user_auth = authenticate(request, username=username, password=password)
                if user_auth is not None:
                    # Reset failed login attempts on successful login
                    user.failed_login_attempts = 0
                    user.save(update_fields=['failed_login_attempts'])
                    # Create audit log entry
                    AuditLog.objects.create(
                        user=user,
                        action='LOGIN_SUCCESS',
                        details='User logged in with password',
                        ip_address=get_client_ip(request)
                    )
                    
                    # Log the user in
                    django_login(request, user_auth)  # Replace auth_login
                    
                    # Determine which dashboard to redirect to
                    if user.role == 'ADMIN':
                        return redirect('core:admin_dashboard')
                    else:
                        return redirect('core:staff_dashboard')
                else:
                    # Increment failed login attempts
                    user.failed_login_attempts += 1
                    user.last_failed_login = timezone.now()
                    user.save(update_fields=['failed_login_attempts', 'last_failed_login'])
                    
                    # Create audit log entry
                    AuditLog.objects.create(
                        user=None,
                        action='LOGIN_FAIL',
                        details=f'Failed login attempt for {username}',
                        ip_address=get_client_ip(request)
                    )
                    
                    messages.error(request, 'Invalid username or password.')
            except User.DoesNotExist:
                # Create audit log entry for non-existent user
                AuditLog.objects.create(
                    user=None,
                    action='LOGIN_FAIL',
                    details=f'Login attempt with non-existent username: {username}',
                    ip_address=get_client_ip(request)
                )
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'core/login.html', {'form': form})

def register(request):
    """User registration view"""
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()
            
            # Create audit log entry
            AuditLog.objects.create(
                user=user,
                action='USER_REGISTER',
                details='User registered',
                ip_address=get_client_ip(request)
            )
            
            # Redirect to the login page with a success message
            messages.success(request, 'Registration successful! Please log in.')
            return redirect('core:login')
    else:
        form = RegistrationForm()
    
    return render(request, 'core/register.html', {'form': form})

@login_required
def logout(request):
    """User logout view"""
    AuditLog.objects.create(
        user=request.user,
        action='LOGOUT',
        details='User logged out',
        ip_address=get_client_ip(request)
    )
    
    django_logout(request)  # Replace auth_logout
    messages.success(request, 'You have been logged out successfully.')
    return redirect('core:login')

def verify_biometrics(request):
    user_id = request.session.get('pending_auth_user_id')
    session_id = request.session.get('pending_auth_session_id')
    
    if not user_id or not session_id:
        return redirect('core:login')
    
    user = get_object_or_404(User, id=user_id)
    session = get_object_or_404(UserSession, id=session_id)
    
    if request.method == 'POST':
        if 'face_image' in request.FILES:
            face_image = request.FILES['face_image']
            try:
                result = verify_face(user, face_image)
                session.face_match_score = result['confidence']
                session.save()
                return JsonResponse({'status': 'success', 'score': result['confidence']})
            except Exception as e:
                logger.error(f"Face verification failed: {str(e)}")
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
        
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
    
    return render(request, 'core/login.html', {
        'user': user,
        'session_id': session_id,
        'show_biometric_verification': True,
        'webauthn_enabled': settings.WEBAUTHN_ENABLED,
    })

@csrf_exempt
@require_http_methods(['POST'])
def webauthn_authentication_options(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    
    # Verify the session contains a valid CSRF token
    csrf_token = request.META.get('HTTP_X_CSRFTOKEN')
    if not csrf_token or not request.session.get('csrf_token') == csrf_token:
        return JsonResponse({'error': 'CSRF validation failed'}, status=403)
    
    user_id = request.session.get('pending_auth_user_id')
    if not user_id:
        return JsonResponse({'error': 'No pending authentication'}, status=400)
    
    user = User.objects.get(id=user_id)
    options = generate_authentication_options(user)
    request.session['webauthn_authentication_challenge'] = options.challenge
    return JsonResponse(options.to_dict())

@csrf_exempt
@require_http_methods(['POST'])
def webauthn_authentication_verify(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    
    user_id = request.session.get('pending_auth_user_id')
    session_id = request.session.get('pending_auth_session_id')
    if not user_id or not session_id:
        return JsonResponse({'error': 'No pending authentication'}, status=400)
    
    user = User.objects.get(id=user_id)
    session = UserSession.objects.get(id=session_id)
    data = json.loads(request.body)
    challenge = request.session.get('webauthn_authentication_challenge')
    
    try:
        credential = verify_authentication_response(user, data, challenge)
        credential.sign_count += 1
        credential.last_used_at = timezone.now()
        credential.save()
        
        session.fingerprint_verified = True
        session.save()
        
        # Finalize authentication
        session = finalize_authentication(request, session)
        
        if session.access_granted:
            django_login(request, user)  # Replace auth_login
            dashboard_url = 'admin_dashboard' if user.role == 'ADMIN' else 'staff_dashboard'
            return JsonResponse({
                'status': 'success',
                'redirect': reverse(f'core:{dashboard_url}')
            })
        else:
            return JsonResponse({
                'status': 'denied',
                'message': 'Access denied due to high risk'
            }, status=403)
    except Exception as e:
        logger.error(f"WebAuthn authentication failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def finalize_authentication(request, session):
    user = session.user
    
    # Get device information
    device_info = get_device_info(request)
    
    # Behavior analysis
    behavior_profile = user.userbehaviorprofile
    current_time = timezone.now().time()
    time_anomaly = 0
    device_anomaly = 0
    fingerprint_anomaly = 0
    is_new_device = False
    
    if behavior_profile.typical_login_time:
        time_diff = abs((datetime.combine(timezone.now().date(), current_time) - 
                        datetime.combine(timezone.now().date(), behavior_profile.typical_login_time)).total_seconds())
        time_anomaly = min(time_diff / 3600, 1)
    
    # Enhanced device detection
    import hashlib
    device_hash = hashlib.sha256(
        f"{device_info['user_agent']}{device_info['browser']}{device_info['os']}".encode()
    ).hexdigest()[:32]
    
    # Check if this is a known device
    known_device = DeviceFingerprint.objects.filter(
        user=user, 
        device_id=device_hash
    ).first()
    
    if behavior_profile.typical_device and behavior_profile.typical_device != session.user_agent:
        device_anomaly = 1
        is_new_device = True
    elif not behavior_profile.typical_device or not known_device:
        # First time login or truly new device
        is_new_device = True
    elif known_device and not known_device.is_trusted:
        # Known but untrusted device
        is_new_device = True
    
    if behavior_profile.typical_device_fingerprint and session.device_fingerprint != behavior_profile.typical_device_fingerprint:
        fingerprint_anomaly = 1
    
    session.behavior_anomaly_score = analyze_behavior_anomaly(user, session) or (
        (time_anomaly + device_anomaly + fingerprint_anomaly) / 3
    )
    
    # Calculate risk score
    session.risk_score = calculate_risk_score(
        face_match_score=session.face_match_score or 0,
        fingerprint_verified=session.fingerprint_verified,
        behavior_anomaly_score=session.behavior_anomaly_score
    )
    
    # Determine risk level
    if session.risk_score < 0.3:
        session.risk_level = 'LOW'
    elif session.risk_score < 0.7:
        session.risk_level = 'MEDIUM'
    else:
        session.risk_level = 'HIGH'
    
    # Apply risk policy
    active_policy = RiskPolicy.objects.filter(is_active=True).first()
    if active_policy:
        risk_level = session.risk_level
        action = getattr(active_policy, f"{risk_level.lower()}_risk_action")
        
        if action == "DENY":
            session.access_granted = False
            session.flagged_reason = f"{risk_level} risk session - access denied by policy"
        elif action == "CHALLENGE":
            session.access_granted = True
            # Send verification notification
            Notification.objects.create(
                user=user,
                message=f'{risk_level.lower()}-risk login detected. Please verify your identity.',
                action_required=True,
                notification_type='RISK'
            )
        else:
            session.access_granted = True
    else:
        session.access_granted = session.risk_level != 'HIGH'
    
    session.save()
    
    # Handle new device notifications and profile updates
    if session.access_granted:
        # Send new device notification if detected
        if is_new_device and hasattr(user, 'profile'):
            # Only send notification if user has email alerts enabled
            if user.profile.receive_email_alerts:
                create_new_device_notification(user, session, device_info)
        
        # Update behavior profile
        if not behavior_profile.typical_login_time:
            behavior_profile.typical_login_time = current_time
        if not behavior_profile.typical_device:
            behavior_profile.typical_device = session.user_agent
        if not behavior_profile.typical_device_fingerprint:
            behavior_profile.typical_device_fingerprint = session.device_fingerprint
        behavior_profile.save()
    
    return session

# --- Dashboard Views ---
@login_required
def dashboard(request):
    # Profile completion gate
    if not hasattr(request.user, 'profile'):
        return redirect('core:complete_profile')
    
    # Biometric enrollment gate
    if not request.user.has_biometrics:
        return redirect('core:register_biometrics')
    
    user = request.user
    sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:5]
    notifications = Notification.objects.filter(user=user, read=False).order_by('-created_at')[:10]
    
    context = {
        'user': user,
        'sessions': sessions,
        'notifications': notifications,
        'risk_policy': RiskPolicy.objects.filter(is_active=True).first()
    }
    
    if user.role == 'ADMIN':
        pending_users = User.objects.filter(is_active=False)
        high_risk_sessions = UserSession.objects.filter(risk_level='HIGH').order_by('-login_time')[:5]
        context.update({
            'pending_users': pending_users,
            'high_risk_sessions': high_risk_sessions
        })
        return render(request, 'core/admin_dashboard.html', context)
    
    return render(request, 'core/staff_dashboard.html', context)

@login_required
def staff_dashboard(request):
    """Staff dashboard view"""
    if request.user.role != 'STAFF':
        messages.error(request, "Access denied. You don't have permission to access this page.")
        return redirect('core:login')
    
    # Update last activity timestamp
    request.user.last_activity = timezone.now()
    request.user.save(update_fields=['last_activity'])
    
    # Get user notifications
    notifications = Notification.objects.filter(user=request.user, read=False)[:5]
    
    context = {
        'user': request.user,
        'notifications': notifications
    }
    
    return render(request, 'core/staff_dashboard.html', context)

@login_required
def admin_dashboard(request):
    """Admin dashboard view"""
    if request.user.role != 'ADMIN':
        messages.error(request, "Access denied. You don't have permission to access this page.")
        return redirect('core:login')
    
    # Update last activity timestamp
    request.user.last_activity = timezone.now()
    request.user.save(update_fields=['last_activity'])
    
    # Get basic stats for the dashboard
    user_count = User.objects.filter(is_active=True).count()
    active_sessions = UserSession.objects.filter(logout_time__isnull=True).count()
    recent_logins = UserSession.objects.select_related('user').order_by('-login_time')[:5]
    security_events = AuditLog.objects.filter(
        timestamp__gte=timezone.now() - timezone.timedelta(hours=24),
        action__in=['ACCESS_DENIED', 'LOGIN_FAIL', 'ACCOUNT_LOCK']
    ).count()
    
    # Get system alerts
    system_alerts = []
    if active_sessions > 50:  # Example threshold
        system_alerts.append({
            'title': 'High number of active sessions',
            'message': f'There are currently {active_sessions} active sessions.',
            'timestamp': timezone.now(),
            'level': 'warning'
        })
    
    context = {
        'user': request.user,
        'user_count': user_count,
        'active_sessions': active_sessions,
        'security_events': security_events,
        'recent_logins': recent_logins,
        'system_alerts': system_alerts,
        'active_tab': 'dashboard'
    }
    
    return render(request, 'core/admin_dashboard.html', context)

# --- Document Vault Views ---
@login_required
def document_list(request):
    user = request.user
    if not hasattr(user, 'profile'):
        return redirect('core:complete_profile')
    documents = Document.objects.filter(deleted=False)

    # Filter by access level
    if user.role != 'ADMIN':
        if hasattr(user, 'profile'):
            documents = documents.filter(
                Q(access_level='PUBLIC') |
                Q(access_level='DEPARTMENT', department=user.profile.department)
            )
        else:
            documents = documents.filter(access_level='PUBLIC')
    
    # Apply search filters
    query = request.GET.get('q', '')
    category = request.GET.get('category', '')
    
    if query:
        documents = documents.filter(Q(title__icontains=query) | Q(description__icontains=query))
    if category:
        documents = documents.filter(category=category)
    
    # Check download permissions
    current_session = UserSession.objects.filter(
        user=user, 
        logout_time__isnull=True
    ).order_by('-login_time').first()
    
    for doc in documents:
        doc.can_download = (
            current_session and
            current_session.access_granted and
            current_session.risk_level == 'LOW' and
            not doc.is_expired()
        )
    
    context = {
        'documents': documents,
        'categories': Document.CATEGORY_CHOICES,
        'query': query,
        'selected_category': category,
        'show_documents': True
    }
    
    if user.role == 'ADMIN':
        return render(request, 'core/admin_dashboard.html', context)
    return render(request, 'core/staff_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def document_upload(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.uploaded_by = request.user
            
            # Encrypt file with user-specific key
            file_data = request.FILES['file'].read()
            encrypted_data = encrypt_file(file_data, request.user)
            
            # Save encrypted file
            doc.file.save(
                f'doc_{int(timezone.now().timestamp())}.enc',
                encrypted_data
            )
            doc.original_filename = request.FILES['file'].name
            
            # Handle versioning
            existing = Document.objects.filter(
                title=doc.title,
                category=doc.category,
                department=doc.department,
                deleted=False
            ).order_by('-version').first()
            
            if existing:
                doc.version = existing.version + 1
                existing.deleted = True
                existing.save()
            
            doc.save()
            return redirect('core:document_list')
    else:
        form = DocumentUploadForm()
    
    return render(request, 'core/admin_dashboard.html', {
        'form': form,
        'show_document_upload': True
    })

@login_required
def document_download(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, deleted=False)
    user = request.user
    if not hasattr(user, 'profile'):
        return redirect('core:complete_profile')

    # Check access permissions
    if user.role != 'ADMIN':
        if doc.access_level == 'PRIVATE' and doc.uploaded_by != user:
            return HttpResponseForbidden("You don't have permission to access this document")
        if doc.access_level == 'DEPARTMENT' and (
            not hasattr(user, 'profile') or doc.department != user.profile.department
        ):
            return HttpResponseForbidden("You don't have permission to access this document")
    
    # Add strict expiry check first
    if doc.is_expired():
        return HttpResponseForbidden("Document expired")
    
    # Check session risk
    current_session = UserSession.objects.filter(
        user=user, 
        logout_time__isnull=True
    ).order_by('-login_time').first()
    
    if not current_session or not current_session.access_granted or current_session.risk_level != 'LOW':
        DocumentAccessLog.objects.create(
            user=user,
            document=doc,
            was_successful=False,
            reason="High-risk session",
            ip_address=get_client_ip(request)
        )
        return redirect('core:access_denied')

    try:
        # Decrypt file with user-specific key
        decrypted_data = decrypt_file(doc.file.read(), doc.uploaded_by)
        
        # Create response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{doc.original_filename}"'
        
        # Log access
        DocumentAccessLog.objects.create(
            user=user,
            document=doc,
            was_successful=True,
            ip_address=get_client_ip(request)
        )
        
        return response
    except (IOError, InvalidToken) as e:
        logger.error(f"Document download failed: {str(e)}")
        return HttpResponseBadRequest("Failed to download document")


@login_required
@user_passes_test(is_admin)
def document_access_logs(request):
    logs = DocumentAccessLog.objects.all().order_by('-timestamp')[:100]
    return render(request, 'core/admin_dashboard.html', {
        'logs': logs,
        'show_document_logs': True
    })


@login_required
@user_passes_test(is_admin)
def purge_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)
    document.deleted = True
    document.save()

    AuditLog.objects.create(
        user=request.user,
        action='DOCUMENT_PURGE',
        details=f'Purged document "{document.title}"',
        ip_address=get_client_ip(request)
    )
    return redirect('core:document_list')

@login_required
@require_POST
def validate_checksum(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)
    try:
        decrypted_data = decrypt_file(document.file.read(), document.uploaded_by)
        checksum = hashlib.sha256(decrypted_data).hexdigest()
        return JsonResponse({'status': 'success', 'checksum': checksum})
    except InvalidToken:
        return JsonResponse({'status': 'error', 'message': 'Checksum validation failed'}, status=400)

# --- Profile Management ---
@login_required
def profile_settings(request):
    user = request.user
    if not hasattr(user, 'profile'):
        return redirect('core:complete_profile')
    profile = user.profile
    
    if request.method == 'POST':
        # Handle password change
        if 'old_password' in request.POST:
            form = CustomPasswordChangeForm(user, request.POST)
            if form.is_valid():
                form.save()
                AuditLog.objects.create(
                    user=user,
                    action='PASSWORD_CHANGE',
                    details='Password changed',
                    ip_address=get_client_ip(request)
                )
                return redirect('core:profile_settings')
        # Handle face re-enrollment
        elif 'face_image' in request.FILES:
            face_image = request.FILES['face_image']
            try:
                face_id = enroll_face(user, face_image)
                user.azure_face_id = face_id
                user.face_data = face_image.read()
                user.save()
                return redirect('core:profile_settings')
            except Exception as e:
                context = {'error': str(e), 'show_profile_settings': True}
                template = 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/staff_dashboard.html'
                return render(request, template, context)
        # Handle profile update
        else:
            form = ProfileUpdateForm(request.POST, request.FILES)
            if form.is_valid():
                # Update user name fields
                user.first_name = form.cleaned_data['first_name']
                user.last_name = form.cleaned_data['last_name']
                
                # Update profile fields
                profile.department = form.cleaned_data['department']
                profile.position = form.cleaned_data['position']
                profile.phone = form.cleaned_data.get('phone_number')
                
                # Handle email update with verification
                if form.cleaned_data['email'] != user.email:
                    # Generate verification token and expiration
                    token = Fernet.generate_key().decode()
                    expiration = timezone.now() + timedelta(hours=24)
                    
                    # Store new email in session and token in DB
                    request.session['pending_email_update'] = form.cleaned_data['email']
                    user.email_verification_token = token
                    user.email_verification_expiration = expiration
                    user.save()
                    
                    # Send verification email
                    verify_url = request.build_absolute_uri(
                        reverse('core:verify_email_update', kwargs={'token': token})
                    )
                    
                    subject = 'Verify Email Change'
                    message = render_to_string('emails/verify_email_update.html', {
                        'user': user,
                        'verify_link': verify_url,
                        'new_email': form.cleaned_data['email']
                    })
                    
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [form.cleaned_data['email']],
                        fail_silently=False
                    )
                    
                    messages.info(request, f"Verification email sent to {form.cleaned_data['email']}. Please verify to complete the email change.")
                
                # Handle profile picture
                if 'profile_picture' in request.FILES:
                    profile.profile_picture = request.FILES['profile_picture']
                
                profile.save()
                
                AuditLog.objects.create(
                    user=user,
                    action='PROFILE_UPDATE',
                    details='Profile information updated',
                    ip_address=get_client_ip(request)
                )
                
                return redirect('core:profile_settings')
    else:
        form = ProfileUpdateForm(initial={
            'first_name': user.first_name,
            'last_name': user.last_name,
            'department': profile.department,
            'position': profile.position,
            'email': user.email,
            'phone_number': profile.phone
        })
    
    context = {
        'profile': profile,
        'profile_form': form,
        'password_form': CustomPasswordChangeForm(user=user),
        'face_form': FaceEnrollForm(),
        'user': user,
        'show_profile_settings': True
    }
    
    template = 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/staff_dashboard.html'
    return render(request, template, context)

# --- Device Management ---
@login_required
def manage_devices(request):
    """View and manage trusted devices"""
    user = request.user
    devices = DeviceFingerprint.objects.filter(user=user).order_by('-last_seen')
    
    context = {
        'devices': devices,
        'show_device_management': True
    }
    
    template = 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/staff_dashboard.html'
    return render(request, template, context)

@login_required
@require_POST
def trust_device(request, device_id):
    """Mark a device as trusted"""
    device = get_object_or_404(DeviceFingerprint, id=device_id, user=request.user)
    device.mark_as_trusted()
    
    AuditLog.objects.create(
        user=request.user,
        action='DEVICE_TRUST',
        details=f'Device marked as trusted: {device}',
        ip_address=get_client_ip(request)
    )
    
    messages.success(request, f'Device "{device}" has been marked as trusted.')
    return redirect('core:manage_devices')

@login_required
@require_POST
def remove_device(request, device_id):
    """Remove/untrust a device"""
    device = get_object_or_404(DeviceFingerprint, id=device_id, user=request.user)
    device_name = str(device)
    device.delete()
    
    AuditLog.objects.create(
        user=request.user,
        action='DEVICE_REMOVE',
        details=f'Device removed: {device_name}',
        ip_address=get_client_ip(request)
    )
    
    messages.success(request, f'Device "{device_name}" has been removed.')
    return redirect('core:manage_devices')

@login_required
@require_POST
def dismiss_device_notification(request, notification_id):
    """Dismiss a device notification and optionally trust the device"""
    notification = get_object_or_404(Notification, id=notification_id, user=request.user, notification_type='DEVICE')
    
    # Check if user wants to trust the device
    trust_device_flag = request.POST.get('trust_device') == 'true'
    device_id = notification.metadata.get('device_id')
    
    if trust_device_flag and device_id:
        try:
            device = DeviceFingerprint.objects.get(device_id=device_id, user=request.user)
            device.mark_as_trusted()
            messages.success(request, 'Device has been marked as trusted.')
        except DeviceFingerprint.DoesNotExist:
            pass
    
    notification.read = True
    notification.save()
    
    return JsonResponse({'status': 'success'})

# --- Notification System ---
@login_required
def notifications_view(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    if request.GET.get('ajax'):
        unread = notifications.filter(read=False).count()
        return JsonResponse({'unread': unread})

    context = {
        'notifications': notifications,
        'show_notifications': True
    }

    if request.user.role == 'ADMIN':
        return render(request, 'core/admin_dashboard.html', context)
    return render(request, 'core/staff_dashboard.html', context)

@login_required
@require_POST
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.read = True
    notification.save()
    return JsonResponse({'status': 'success'})

# --- Policy Management ---
@login_required
@user_passes_test(is_admin)
def policy_editor(request):
    policy = RiskPolicy.objects.filter(is_active=True).first()
    
    if request.method == 'POST':
        form = RiskPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            new_policy = form.save(commit=False)
            
            # Deactivate previous policy
            if policy:
                policy.is_active = False
                policy.save()
            
            new_policy.is_active = True
            new_policy.save()
            return redirect('core:admin_dashboard')
    else:
        form = RiskPolicyForm(instance=policy)
    
    return render(request, 'core/admin_dashboard.html', {
        'form': form,
        'show_policy_editor': True
    })

# --- Audit Logs ---
@login_required
@user_passes_test(is_admin)
def audit_logs(request):
    logs = AuditLog.objects.all().order_by('-timestamp')[:100]
    return render(request, 'core/admin_dashboard.html', {
        'logs': logs,
        'show_audit_logs': True
    })

@login_required
@user_passes_test(is_admin)
def export_audit_logs(request):
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
    
    # Filter params
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action = request.GET.get('action')
    user_id = request.GET.get('user_id')
    
    logs = AuditLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        try:
            start = timezone.datetime.strptime(start_date, '%Y-%m-%d')
            logs = logs.filter(timestamp__gte=start)
        except ValueError:
            pass
    
    if end_date:
        try:
            end = timezone.datetime.strptime(end_date, '%Y-%m-%d')
            logs = logs.filter(timestamp__lte=end)
        except ValueError:
            pass
    
    if action:
        logs = logs.filter(action=action)
    
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'Details', 'IP Address'])
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'System',
            log.action,
            log.details,
            log.ip_address
        ])
    
    return response

# --- Admin Actions ---
@login_required
@user_passes_test(is_admin)
def lock_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = False
    user.save()
    return redirect('core:admin_dashboard')

@login_required
@user_passes_test(is_admin)
def unlock_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = True
    user.save()
    return redirect('core:admin_dashboard')

@login_required
@user_passes_test(is_admin)
def force_reenroll(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.FACE_ENROLLED = False
    user.FINGERPRINT_ENROLLED = False
    user.save()
    return redirect('core:admin_dashboard')

# --- Password Reset ---
def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                
                # Generate token and expiration
                token = Fernet.generate_key().decode()
                expiration = timezone.now() + timedelta(hours=24)
                
                user.email_verification_token = token
                user.email_verification_expiration = expiration
                user.save()
                
                # Send password reset email
                reset_url = request.build_absolute_uri(
                    reverse('core:password_reset_confirm', kwargs={'user_id': user.id, 'token': token})
                )
                
                subject = 'Password Reset Request'
                message = render_to_string('emails/password_reset.html', {
                    'user': user,
                    'reset_link': reset_url
                })
                
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False
                )
                
                return render(request, 'core/password_reset_done.html')
            except User.DoesNotExist:
                # Still return success to prevent email enumeration
                return render(request, 'core/password_reset_done.html')
    else:
        form = PasswordResetForm()
    
    return render(request, 'core/password_reset.html', {'form': form})

def password_reset_confirm(request, user_id, token):
    user = get_object_or_404(User, id=user_id)
    
    # Check token and expiration
    if user.email_verification_token != token or user.email_verification_expiration < timezone.now():
        return render(request, 'core/login.html', {
            'error': 'Password reset link is invalid or has expired.'
        })
    
    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            user.set_password(new_password)
            user.email_verification_token = None
            user.email_verification_expiration = None
            user.save()
            
            AuditLog.objects.create(
                user=user,
                action='PASSWORD_RESET',
                details='Password reset via email link',
                ip_address=get_client_ip(request)
            )
            
            return redirect('core:login')
    else:
        form = PasswordResetConfirmForm()
    
    return render(request, 'core/password_reset_confirm.html', {'form': form})

# --- Access Denied View ---
def access_denied(request):
    reason = request.GET.get('reason', 'Access denied due to security policy')
    context = {
        'reason': reason,
        'show_access_denied': True
    }
    
    if request.user.is_authenticated:
        template = 'core/admin_dashboard.html' if request.user.role == 'ADMIN' else 'core/staff_dashboard.html'
        return render(request, template, context)
    return render(request, 'core/login.html', context)

# --- Email Update Verification ---
def verify_email_update(request, token):
    user = get_object_or_404(User, email_verification_token=token)
    
    # Check token and expiration
    if user.email_verification_expiration < timezone.now():
        return render(request, 'core/login.html', {
            'error': 'Email verification link has expired.'
        })
    
    # Get the pending email from session
    new_email = request.session.get('pending_email_update')
    if not new_email:
        return render(request, 'core/login.html', {
            'error': 'Email update session has expired.'
        })
    
    # Update the email
    old_email = user.email
    user.email = new_email
    user.email_verification_token = None
    user.email_verification_expiration = None
    user.save()
    
    # Log the change
    AuditLog.objects.create(
        user=user,
        action='EMAIL_CHANGE',
        details=f'Email changed from {old_email} to {new_email}',
        ip_address=get_client_ip(request)
    )
    
    # Clear the session
    if 'pending_email_update' in request.session:
        del request.session['pending_email_update']
    
    # Notify user of successful change
    messages.success(request, 'Your email has been successfully updated.')
    
    # Redirect to profile if logged in, otherwise to login
    if request.user.is_authenticated:
        return redirect('core:profile_settings')
    return redirect('core:login')
