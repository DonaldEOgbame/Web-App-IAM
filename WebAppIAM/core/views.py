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
from django.middleware.csrf import get_token
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

from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn import verify_registration_response as lib_verify_registration_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticatorAttestationResponse
from webauthn.helpers.exceptions import InvalidRegistrationResponse

import numpy as np

from .models import (
    User, UserProfile, UserBehaviorProfile, WebAuthnCredential,
    UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog,
    Notification, DeviceFingerprint
)
from .models_keystroke import KeystrokeDynamics
from .webauthn_utils import (
    generate_registration_options,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from .face_api import verify_face, enroll_face, FaceAPIError
from .risk_engine import calculate_risk_score, analyze_behavior_anomaly
from .forms import (
    RegistrationForm, LoginForm, FaceEnrollForm, FingerprintReRegisterForm,
    RiskPolicyForm, ReportSubmissionForm, CustomPasswordChangeForm,
    DocumentUploadForm, DocumentEditForm, ProfileCompletionForm,
    ProfileUpdateForm, PasswordResetForm, PasswordResetConfirmForm
)

logger = logging.getLogger(__name__)

# -------------------- Encryption Utilities --------------------
def get_fernet_key(user=None):
    if user:
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

# -------------------- Utilities & Helpers --------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

def get_device_info(request):
    ua = request.META.get('HTTP_USER_AGENT', '')

    device_type = 'Desktop'
    if 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua:
        device_type = 'Mobile'
    elif 'Tablet' in ua or 'iPad' in ua:
        device_type = 'Tablet'

    browser = 'Unknown'
    if 'Chrome' in ua:
        browser = 'Chrome'
    elif 'Firefox' in ua:
        browser = 'Firefox'
    elif 'Safari' in ua and 'Chrome' not in ua:
        browser = 'Safari'
    elif 'Edge' in ua:
        browser = 'Edge'

    os = 'Unknown'
    if 'Windows' in ua:
        os = 'Windows'
    elif 'Mac' in ua:
        os = 'macOS'
    elif 'Linux' in ua:
        os = 'Linux'
    elif 'Android' in ua:
        os = 'Android'
    elif 'iOS' in ua or 'iPhone' in ua or 'iPad' in ua:
        os = 'iOS'

    return {
        'device_type': device_type,
        'browser': browser,
        'os': os,
        'user_agent': ua
    }

def get_registration_user(request):
    if request.user.is_authenticated:
        return request.user
    pending_id = request.session.get('pending_user_id')
    if pending_id:
        return get_object_or_404(User, id=pending_id)
    return None

def rate_limit(request, key_prefix, limit=5, window=60):
    key = f"rate:{key_prefix}:{get_client_ip(request)}"
    count = cache.get(key, 0)
    if count >= limit:
        return False
    cache.set(key, count + 1, timeout=window)
    return True

def notify_admin(subject, context):
    admins = User.objects.filter(role='ADMIN', is_active=True)
    admin_emails = [a.email for a in admins if a.email]
    if admin_emails:
        send_mail(subject, context, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)

def is_admin(user):
    if not getattr(user, "is_authenticated", False):
        return False
    return user.is_superuser or getattr(user, "role", None) == "ADMIN"

def has_granted_access(user):
    """Check if user has both authentication and granted access from risk assessment"""
    if not getattr(user, "is_authenticated", False):
        return False
    
    # Get the user's current session
    try:
        session = UserSession.objects.filter(user=user).order_by('-login_time').first()
        if not session:
            return False
        return session.access_granted
    except UserSession.DoesNotExist:
        return False

def access_granted_required(view_func):
    """Decorator that requires both login and granted access from risk assessment"""
    @login_required
    def wrapper(request, *args, **kwargs):
        if has_granted_access(request.user):
            return view_func(request, *args, **kwargs)
        else:
            # Redirect to access denied page if access not granted
            return redirect(f"{reverse('core:access_denied')}?reason=Access%20denied%20by%20risk%20assessment")
    return wrapper

def log_security_event(request, event_type, details, success=False):
    user = request.user if request.user.is_authenticated else None
    username = user.username if user else request.POST.get('username', 'anonymous')
    AuditLog.objects.create(
        user=user,
        action=f"SECURITY_{event_type}",
        details=details,
        ip_address=get_client_ip(request)
    )
    msg = f"Security event: {event_type} | User: {username} | IP: {get_client_ip(request)} | Success: {success} | Details: {details}"
    (logger.info if success else logger.warning)(msg)

# ---- Keystroke helpers ----
def _extract_keystroke_stats(event_data):
    if not event_data:
        return np.nan, np.nan
    holds, flights = [], []
    last_up = None
    for ev in event_data:
        try:
            down = ev.get("down")
            up = ev.get("up")
            if down is not None and up is not None and up >= down:
                holds.append(float(up) - float(down))
            if last_up is not None and down is not None:
                flights.append(float(down) - float(last_up))
            if up is not None:
                last_up = float(up)
        except Exception:
            continue
    h = float(np.mean(holds)) if len(holds) >= 3 else np.nan
    f = float(np.mean(flights)) if len(flights) >= 3 else np.nan
    return h, f

def _compute_keystroke_anomaly(user, this_session_id=None, min_history=5):
    try:
        qs = KeystrokeDynamics.objects.filter(user=user).order_by('-created_at')
        if this_session_id:
            qs = qs.exclude(session_id=this_session_id)
        history = list(qs[:50])
        if len(history) < min_history:
            return 0.5

        H, F = [], []
        for row in history:
            h, f = _extract_keystroke_stats(row.event_data or [])
            if np.isfinite(h): H.append(h)
            if np.isfinite(f): F.append(f)
        if len(H) < min_history or len(F) < min_history:
            return 0.5

        h_mu, h_sigma = float(np.mean(H)), float(np.std(H) + 1e-6)
        f_mu, f_sigma = float(np.mean(F)), float(np.std(F) + 1e-6)

        cur = None
        if this_session_id:
            cur = KeystrokeDynamics.objects.filter(user=user, session_id=this_session_id).order_by('-created_at').first()
        if not cur:
            cur = KeystrokeDynamics.objects.filter(user=user).order_by('-created_at').first()
        if not cur:
            return 0.5

        h_cur, f_cur = _extract_keystroke_stats(cur.event_data or [])
        if not (np.isfinite(h_cur) and np.isfinite(f_cur)):
            return 0.5

        z = np.sqrt(((h_cur - h_mu) / h_sigma) ** 2 + ((f_cur - f_mu) / f_sigma) ** 2)
        anomaly = float(1.0 - np.exp(-z / 2.0))
        return max(0.0, min(1.0, anomaly))
    except Exception as e:
        logger.warning(f"Keystroke anomaly computation failed: {e}")
        return 0.5

# -------------------- Dashboard Context Builders --------------------
def _role_template(user):
    return 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/staff_dashboard.html'

def _staff_base_context(user):
    # Filter documents: show ALL department documents + user's department documents
    documents = Document.objects.filter(
        deleted=False,
        access_level='DEPT',
        required_access_level__gte=user.profile.access_level,
    ).filter(
        Q(department=user.profile.department) | Q(department='ALL')
    )
    sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:5]
    notifications = Notification.objects.filter(user=user, read=False).order_by('-created_at')[:10]
    devices = DeviceFingerprint.objects.filter(user=user).order_by('-last_seen')
    return {
        'user': user,
        'documents': documents,
        'sessions': sessions,
        'notifications': notifications,
        'devices': devices,
        'risk_policy': RiskPolicy.objects.filter(is_active=True).first(),
    }

def _admin_base_context(user):
    user_count = User.objects.filter(is_active=True).count()
    active_sessions = UserSession.objects.filter(logout_time__isnull=True).count()
    recent_logins = UserSession.objects.select_related('user').order_by('-login_time')[:5]
    security_events = AuditLog.objects.filter(
        timestamp__gte=timezone.now() - timezone.timedelta(hours=24),
        action__in=['ACCESS_DENIED', 'LOGIN_FAIL', 'ACCOUNT_LOCK']
    ).count()
    high_risk_sessions = get_latest_high_risk_sessions()
    documents = Document.objects.filter(deleted=False)
    audit_logs = AuditLog.objects.all().order_by('-timestamp')[:100]
    devices = DeviceFingerprint.objects.filter(user=user).order_by('-last_seen')
    notifications = Notification.objects.filter(user=user, read=False).order_by('-created_at')[:10]
    users = User.objects.all().select_related('profile')
    pending_users = User.objects.filter(is_active=False)
    system_alerts = []
    if active_sessions > 50:
        system_alerts.append({
            'title': 'High number of active sessions',
            'message': f'There are currently {active_sessions} active sessions.',
            'timestamp': timezone.now(),
            'level': 'warning'
        })
    return {
        'user': user,
        'user_count': user_count,
        'active_sessions': active_sessions,
        'security_events': security_events,
        'recent_logins': recent_logins,
        'high_risk_sessions': high_risk_sessions,
        'documents': documents,
        'audit_logs': audit_logs,
        'devices': devices,
        'notifications': notifications,
        'users': users,
        'pending_users': pending_users,
        'system_alerts': system_alerts,
        'form': DocumentUploadForm(),
        'show_document_upload': True,
    }

def _redirect_to_tab(request, tab: str):
    """Redirect to the right dashboard with ?tab=..."""
    dest = 'core:admin_dashboard' if request.user.role == 'ADMIN' else 'core:staff_dashboard'
    url = f"{reverse(dest)}?tab={tab}"
    return redirect(url)

def create_new_device_notification(user, session, device_info):
    device_hash = hashlib.sha256(
        f"{device_info['user_agent']}{device_info['browser']}{device_info['os']}".encode()
    ).hexdigest()[:32]

    device_fp, created = DeviceFingerprint.objects.get_or_create(
        user=user,
        device_id=device_hash,
        defaults={
            'browser': device_info['browser'],
            'operating_system': device_info['os'],
            'device_type': device_info['device_type'],
            'user_agent': device_info['user_agent'],
            'last_ip': session.ip_address,
            'last_location': session.location,
        },
    )

    if not created:
        device_fp.update_usage(session.ip_address, session.location)
        if device_fp.is_trusted:
            return

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

def get_latest_high_risk_sessions(limit=5):
    sessions = (
        UserSession.objects.filter(risk_level='HIGH', access_granted=False)
        .order_by('-login_time')
    )
    unique, seen = [], set()
    for s in sessions:
        if s.user_id in seen:
            continue
        seen.add(s.user_id)
        unique.append(s)
        if limit and len(unique) >= limit:
            break
    return unique

# -------------------- Account Lifecycle --------------------
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

    notify_admin('New User Registration', f'User {username} ({email}) registered and pending approval.')
    return JsonResponse({'status': 'success', 'message': 'User created. Pending admin activation.'})

@login_required
@user_passes_test(is_admin)
@require_POST
def activate_user(request, user_id):
    user = get_object_or_404(User, id=user_id, is_active=False)
    user.is_active = True
    user.save()
    AuditLog.objects.create(
        user=request.user,
        affected_user=user,
        action='USER_ACTIVATE',
        details=f'Activated user {user.username}',
        ip_address=get_client_ip(request)
    )
    send_mail('Account Approved',
              'Your account has been approved by the administrator. You can now log in to the platform.',
              settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
    return redirect('core:admin_dashboard')

def complete_profile(request):
    user_id = request.session.get('complete_profile_user')
    if not user_id:
        return redirect('core:login')
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        form = ProfileCompletionForm(request.POST)
        if form.is_valid():
            UserProfile.objects.create(
                user=user,
                department=form.cleaned_data['department'],
                position=form.cleaned_data['position']
            )
            user.first_name = form.cleaned_data['first_name']
            user.last_name = form.cleaned_data['last_name']
            user.save()
            request.session.pop('pending_user_id', None)
            request.session.pop('complete_profile_user', None)
            return render(request, 'core/pending_approval.html', {'user': user})
    else:
        form = ProfileCompletionForm()

    return render(request, 'core/complete_profile.html', {'form': form, 'user': user})

def register_biometrics(request):
    user = None
    if request.user.is_authenticated:
        user = request.user
    elif request.session.get('pending_user_id'):
        user = get_object_or_404(User, id=request.session['pending_user_id'])
    if not user:
        return redirect('core:login')

    if user.has_biometrics and not user.force_reenroll:
        messages.info(request, 'Biometrics already enrolled.')
        if request.user.is_authenticated:
            return redirect('core:admin_dashboard' if user.role == 'ADMIN' else 'core:staff_dashboard')
        return redirect('core:login')

    if request.method == 'POST':
        if 'face_data' in request.FILES:
            try:
                face_data = request.FILES['face_data'].read()
                if enroll_face(user, face_data):
                    user.save(update_fields=[])
                    request.session['complete_profile_user'] = user.id
                    return redirect('core:complete_profile')
                messages.error(request, 'Face enrollment failed.')
            except FaceAPIError as e:
                messages.error(request, str(e))
            except Exception:
                logger.exception("Face enrollment error")
                messages.error(request, 'Server error during face enrollment.')
            return redirect('core:register_biometrics')

        messages.error(request, 'No face data provided.')
        return redirect('core:register_biometrics')

    options = None
    if not getattr(user, 'face_data', None):
        options = generate_registration_options(user)
        request.session['webauthn_registration_challenge'] = bytes_to_base64url(options.challenge)

    return render(
        request,
        'core/enroll_biometrics.html',
        {'webauthn_options': json.loads(options_to_json(options)) if options else None},
    )

def webauthn_registration_options(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    user = get_registration_user(request)
    if not user:
        return JsonResponse({'error': 'Authentication required'}, status=403)
    if user.has_biometrics and not user.force_reenroll:
        return JsonResponse({'error': 'Biometrics already enrolled'}, status=400)
    options = generate_registration_options(user)
    request.session['webauthn_registration_challenge'] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

def _expected_origin(request):
    origin = getattr(settings, "WEBAUTHN_ORIGIN", "").strip()
    if origin:
        return origin
    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{request.get_host()}"

def _expected_rp_id(request):
    rp_id = getattr(settings, "WEBAUTHN_RP_ID", "").strip()
    if rp_id:
        return rp_id
    return request.get_host().split(":")[0]

def webauthn_registration_verify(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)

    user = get_registration_user(request)
    if not user:
        return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=403)

    has_passkey = WebAuthnCredential.objects.filter(user=user).exists()
    if has_passkey and not user.force_reenroll:
        return JsonResponse({'status': 'error', 'message': 'Passkey already enrolled'}, status=400)

    challenge_b64u = request.session.get('webauthn_registration_challenge')
    if not challenge_b64u:
        return JsonResponse({'status': 'error', 'message': 'Challenge missing or expired'}, status=400)
    try:
        expected_challenge = base64url_to_bytes(challenge_b64u)
    except Exception:
        return JsonResponse({'status': 'error', 'message': 'Invalid stored challenge'}, status=400)

    try:
        data = json.loads(request.body.decode('utf-8'))
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Invalid JSON: {e}'}, status=400)

    try:
        cred = RegistrationCredential(
            id=data["id"],
            raw_id=base64url_to_bytes(data["rawId"]),
            type=data.get("type", "public-key"),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
                attestation_object=base64url_to_bytes(data["response"]["attestationObject"]),
                transports=data.get("response", {}).get("transports", []),
            ),
        )
    except KeyError as e:
        return JsonResponse({'status': 'error', 'message': f'Missing field: {e}'}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Invalid credential payload: {e}'}, status=400)

    expected_origin = _expected_origin(request)
    expected_rp_id = _expected_rp_id(request)

    try:
        verification = lib_verify_registration_response(
            credential=cred,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as e:
        logger.warning("WebAuthn registration verify failed: %s", e)
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception:
        logger.exception("Unexpected WebAuthn registration error")
        return JsonResponse({'status': 'error', 'message': 'Verification failed'}, status=400)

    try:
        cred_id_b64u = bytes_to_base64url(verification.credential_id)
        pubkey_b64u = bytes_to_base64url(verification.credential_public_key)
        sign_count = int(getattr(verification, "sign_count", 0) or 0)
        WebAuthnCredential.objects.create(
            user=user,
            credential_id=cred_id_b64u,
            public_key=pubkey_b64u,
            sign_count=sign_count,
            last_used_at=timezone.now(),
        )
    except Exception:
        logger.exception("Failed to persist WebAuthn credential")
        return JsonResponse({'status': 'error', 'message': 'Could not save credential'}, status=500)

    request.session['complete_profile_user'] = user.id
    request.session.pop('webauthn_registration_challenge', None)

    AuditLog.objects.create(
        user=user,
        action='FINGERPRINT_ENROLL',
        details='Fingerprint enrolled',
        ip_address=get_client_ip(request)
    )

    return JsonResponse({'status': 'success', 'redirect': reverse('core:complete_profile')})

# -------------------- Authentication --------------------
def login(request):
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        form = LoginForm(request.POST)

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

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            try:
                user = User.objects.get(username=username)

                if user.failed_login_attempts >= settings.MAX_FAILED_LOGINS:
                    if user.last_failed_login and timezone.now() < user.last_failed_login + timezone.timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES):
                        AuditLog.objects.create(
                            user=None, action='LOGIN_FAIL',
                            details=f'Login attempt on locked account: {username}',
                            ip_address=get_client_ip(request)
                        )
                        messages.error(request, f'Account locked due to too many failed attempts. Try again in {settings.ACCOUNT_LOCKOUT_MINUTES} minutes.')
                        return render(request, 'core/login.html', {'form': form})
                    else:
                        user.failed_login_attempts = 0
                        user.save(update_fields=['failed_login_attempts'])

                if not user.is_active:
                    messages.error(request, 'Your account is pending administrator approval.')
                    return render(request, 'core/login.html', {'form': form})

                user_auth = authenticate(request, username=username, password=password)
                if user_auth is not None:
                    user.failed_login_attempts = 0
                    user.save(update_fields=['failed_login_attempts'])

                    AuditLog.objects.create(
                        user=user, action='LOGIN_SUCCESS',
                        details='User logged in with password',
                        ip_address=get_client_ip(request)
                    )

                    django_login(request, user_auth)
                    get_token(request)

                    session_key = getattr(request.session, 'session_key', None)
                    if isinstance(request.session, dict):
                        session_key = request.session.get('session_key')
                    if session_key is None:
                        session_key = ''
                    session_obj = UserSession.objects.create(
                        user=user,
                        session_key=session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        device_fingerprint=request.session.get('security_fingerprint')
                    )
                    request.session['pending_auth_user_id'] = user.id
                    request.session['pending_auth_session_id'] = session_obj.id

                    device_info = get_device_info(request)
                    device_hash = hashlib.sha256(
                        f"{device_info['user_agent']}{device_info['browser']}{device_info['os']}".encode()
                    ).hexdigest()[:32]
                    device_fp, created = DeviceFingerprint.objects.get_or_create(
                        user=user,
                        device_id=device_hash,
                        defaults={
                            'browser': device_info['browser'],
                            'operating_system': device_info['os'],
                            'device_type': device_info['device_type'],
                            'user_agent': device_info['user_agent'],
                            'last_ip': get_client_ip(request),
                        },
                    )
                    if not created:
                        device_fp.update_usage(get_client_ip(request))

                    next_url = reverse('core:admin_dashboard') if user.role == 'ADMIN' else reverse('core:staff_dashboard')

                    if is_ajax:
                        if user.has_biometrics:
                            return JsonResponse({
                                'status': 'password_ok_biometric_required',
                                'face': bool(user.face_data),
                                'webauthn': user.webauthn_credentials.exists(),
                                'next': next_url
                            })
                        else:
                            return JsonResponse({'status': 'ok', 'next': next_url})

                    return redirect(next_url)
                else:
                    user.failed_login_attempts += 1
                    user.last_failed_login = timezone.now()
                    user.save(update_fields=['failed_login_attempts', 'last_failed_login'])

                    AuditLog.objects.create(
                        user=None, action='LOGIN_FAIL',
                        details=f'Failed login attempt for {username}',
                        ip_address=get_client_ip(request)
                    )
                    if is_ajax:
                        return JsonResponse({'status': 'error', 'message': 'Invalid username or password.'}, status=400)
                    messages.error(request, 'Invalid username or password.')
            except User.DoesNotExist:
                AuditLog.objects.create(
                    user=None, action='LOGIN_FAIL',
                    details=f'Login attempt with non-existent username: {username}',
                    ip_address=get_client_ip(request)
                )
                if is_ajax:
                    return JsonResponse({'status': 'error', 'message': 'Invalid username or password.'}, status=400)
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()

    get_token(request)
    return render(request, 'core/login.html', {'form': form})

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.set_password(form.cleaned_data['password1'])
            user.save()
            AuditLog.objects.create(
                user=user, action='USER_REGISTER', details='User registered',
                ip_address=get_client_ip(request)
            )
            request.session['pending_user_id'] = user.id
            return redirect('core:register_biometrics')
    else:
        form = RegistrationForm()
    return render(request, 'core/register.html', {'form': form})

@login_required
def logout(request):
    AuditLog.objects.create(
        user=request.user,
        action='LOGOUT',
        details='User logged out',
        ip_address=get_client_ip(request)
    )
    session = UserSession.objects.filter(user=request.user, logout_time__isnull=True).order_by('-login_time').first()
    if session:
        session.logout_time = timezone.now()
        session.save(update_fields=['logout_time'])

    django_logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('core:login')

def verify_biometrics(request):
    user_id = request.session.get('pending_auth_user_id')
    session_id = request.session.get('pending_auth_session_id')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if not user_id or not session_id:
        if is_ajax:
            return JsonResponse({'status': 'error', 'message': 'No pending authentication'}, status=400)
        return redirect('core:login')

    user = get_object_or_404(User, id=user_id)
    session = get_object_or_404(UserSession, id=session_id)

    if request.method == 'POST':
        image = request.FILES.get('face_image') or request.FILES.get('face_data')
        if not image:
            if is_ajax:
                return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
            messages.error(request, 'Invalid request.')
            return redirect('core:login')

        try:
            result = verify_face(user, image)
            session.face_match_score = result['confidence']
            session.save()

            session = finalize_authentication(request, session)
            if session.access_granted:
                django_login(request, user)
                dashboard_url = 'core:admin_dashboard' if user.role == 'ADMIN' else 'core:staff_dashboard'
                if is_ajax:
                    return JsonResponse({'status': 'success', 'score': result['confidence'], 'next': reverse(dashboard_url)})
                return redirect(dashboard_url)

            if is_ajax:
                return JsonResponse({
                    'status': 'denied',
                    'message': 'Access denied due to high risk',
                    'next': f"{reverse('core:access_denied')}?reason=High%20risk"
                })
            return redirect(f"{reverse('core:access_denied')}?reason=High%20risk")

        except FaceAPIError as e:
            logger.warning(f"Face verification failed: {e}")
            messages.error(request, str(e))
            if is_ajax:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            return redirect('core:login')
        except Exception as e:
            logger.exception("Unexpected face verification error")
            messages.error(request, 'Face verification temporarily unavailable.')
            if is_ajax:
                return JsonResponse({'status': 'error', 'message': f'Face verification failed: {str(e)}'}, status=500)
            return redirect('core:login')

    try:
        if is_ajax:
            return JsonResponse({'status': 'error', 'message': 'Invalid request method for biometric verification. POST required.'}, status=400)
        return render(request, 'core/login.html', {
            'user': user,
            'session_id': session_id,
            'show_biometric_verification': True,
            'webauthn_enabled': settings.WEBAUTHN_ENABLED,
        })
    except Exception as e:
        logger.exception("Error rendering biometric login page")
        if is_ajax:
            return JsonResponse({'status': 'error', 'message': f'Server error during biometric verification: {str(e)}'}, status=500)
        messages.error(request, 'Server error during biometric verification.')
        return redirect('core:login')

@require_http_methods(['POST'])
def webauthn_authentication_options(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    user_id = request.session.get('pending_auth_user_id')
    if not user_id:
        return JsonResponse({'error': 'No pending authentication'}, status=400)
    user = User.objects.get(id=user_id)
    options = generate_authentication_options(user)
    request.session['webauthn_authentication_challenge'] = bytes_to_base64url(options.challenge)
    return JsonResponse(json.loads(options_to_json(options)))

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
    if isinstance(challenge, str):
        challenge = base64url_to_bytes(challenge)

    try:
        credential = verify_authentication_response(user, data, challenge)
        credential.sign_count += 1
        credential.last_used_at = timezone.now()
        credential.save()

        session.fingerprint_verified = True
        session.save()

        session = finalize_authentication(request, session)
        if session.access_granted:
            django_login(request, user)
            dashboard_url = 'admin_dashboard' if user.role == 'ADMIN' else 'staff_dashboard'
            return JsonResponse({'status': 'success', 'next': reverse(f'core:{dashboard_url}')})
        else:
            return JsonResponse({'status': 'denied', 'message': 'Access denied due to high risk'}, status=403)
    except Exception as e:
        logger.error(f"WebAuthn authentication failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def finalize_authentication(request, session):
    user = session.user
    device_info = get_device_info(request)
    behavior_profile, _ = UserBehaviorProfile.objects.get_or_create(user=user)
    current_time = timezone.now().time()
    time_anomaly = 0
    device_anomaly = 0
    fingerprint_anomaly = 0
    is_new_device = False

    if behavior_profile.typical_login_time:
        time_diff = abs((datetime.combine(timezone.now().date(), current_time) -
                        datetime.combine(timezone.now().date(), behavior_profile.typical_login_time)).total_seconds())
        time_anomaly = min(time_diff / 3600, 1)

    device_hash = hashlib.sha256(
        f"{device_info['user_agent']}{device_info['browser']}{device_info['os']}".encode()
    ).hexdigest()[:32]

    known_device = DeviceFingerprint.objects.filter(user=user, device_id=device_hash).first()

    if behavior_profile.typical_device and behavior_profile.typical_device != session.user_agent:
        device_anomaly = 1; is_new_device = True
    elif not behavior_profile.typical_device or not known_device:
        device_anomaly = 1; is_new_device = True
    elif known_device and not known_device.is_trusted:
        device_anomaly = 1; is_new_device = True
    else:
        device_anomaly = 0

    if behavior_profile.typical_device_fingerprint and session.device_fingerprint != behavior_profile.typical_device_fingerprint:
        fingerprint_anomaly = 1

    session.time_anomaly = time_anomaly
    session.device_anomaly = device_anomaly
    session.location_anomaly = getattr(session, 'location_anomaly', 0)

    session.behavior_anomaly_score = analyze_behavior_anomaly(session) or (
        (time_anomaly + device_anomaly + fingerprint_anomaly) / 3
    )

    try:
        keystroke_anomaly = _compute_keystroke_anomaly(user, this_session_id=session.session_key)
    except Exception as e:
        logger.warning(f"Keystroke anomaly error: {e}")
        keystroke_anomaly = 0.5
    session.keystroke_anomaly = keystroke_anomaly

    session.risk_score = calculate_risk_score(
        face_match=session.face_match_score or 0,
        fingerprint_verified=session.fingerprint_verified,
        behavior_anomaly=session.behavior_anomaly_score,
        keystroke_anomaly=keystroke_anomaly,
    )
    if known_device and known_device.is_trusted:
        session.risk_score = max(session.risk_score - 0.1, 0)

    if session.risk_score < 0.3:
        session.risk_level = 'LOW'
    elif session.risk_score < 0.7:
        session.risk_level = 'MEDIUM'
    else:
        session.risk_level = 'HIGH'

    if getattr(user, 'admin_high_risk_override', False):
        session.access_granted = True
        session.flagged_reason = 'Admin override: high risk bypassed'
        user.admin_high_risk_override = False
        user.save(update_fields=["admin_high_risk_override"])

        if session.device_fingerprint:
            device, _ = DeviceFingerprint.objects.get_or_create(
                user=user,
                device_id=session.device_fingerprint,
                defaults={
                    'browser': device_info.get('browser', ''),
                    'operating_system': device_info.get('os', ''),
                    'device_type': device_info.get('device_type', 'Desktop'),
                    'user_agent': device_info.get('user_agent', ''),
                    'last_ip': session.ip_address,
                    'last_location': session.location,
                },
            )
            if not device.is_trusted:
                device.mark_as_trusted()
    else:
        active_policy = RiskPolicy.objects.filter(is_active=True).first()
        if active_policy:
            risk_level = session.risk_level
            action = getattr(active_policy, f"{risk_level.lower()}_risk_action")
            if action == "DENY":
                session.access_granted = False
                session.flagged_reason = f"{risk_level} risk session - access denied by policy"
            elif action == "CHALLENGE":
                session.access_granted = True
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

    if session.access_granted:
        if is_new_device and hasattr(user, 'profile') and user.profile.receive_email_alerts:
            create_new_device_notification(user, session, device_info)
        if not behavior_profile.typical_login_time:
            behavior_profile.typical_login_time = current_time
        if not behavior_profile.typical_device:
            behavior_profile.typical_device = session.user_agent
        if not behavior_profile.typical_device_fingerprint:
            behavior_profile.typical_device_fingerprint = session.device_fingerprint
        behavior_profile.save()

    return session

# -------------------- Dashboards --------------------
@access_granted_required
def dashboard(request):
    """
    Generic dashboard router; preserves SPA behavior.
    Ensures profile forms are present when ?tab=profile.
    """
    if not hasattr(request.user, 'profile'):
        request.session['complete_profile_user'] = request.user.id
        return redirect('core:complete_profile')

    if not request.user.has_biometrics:
        return redirect('core:register_biometrics')

    user = request.user
    tab = request.GET.get('tab', 'dashboard')

    if user.role == 'ADMIN':
        context = _admin_base_context(user)
        # Inject profile forms if the profile tab is requested
        if tab == 'profile':
            profile = getattr(user, 'profile', None)
            if profile:
                context['profile_form'] = ProfileUpdateForm(initial={
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'department': profile.department,
                    'position': profile.position,
                    'email': user.email,
                    'phone': profile.phone,
                    'show_risk_alerts': profile.show_risk_alerts,
                    'auto_logout': profile.auto_logout,
                    'receive_email_alerts': profile.receive_email_alerts,
                })
                context['password_form'] = CustomPasswordChangeForm(user=user)
                context['show_profile_settings'] = True
        context.update({
            'active_tab': tab,
            'show_documents': True,
            'show_audit_logs': True,
            'show_device_management': True,
            'show_notifications': True,
        })
        return render(request, 'core/admin_dashboard.html', context)

    # STAFF
    context = _staff_base_context(user)
    if tab == 'profile':
        profile = getattr(user, 'profile', None)
        if profile:
            context['profile_form'] = ProfileUpdateForm(initial={
                'first_name': user.first_name,
                'last_name': user.last_name,
                'department': profile.department,
                'position': profile.position,
                'email': user.email,
                'phone': profile.phone,
                'show_risk_alerts': profile.show_risk_alerts,
                'auto_logout': profile.auto_logout,
                'receive_email_alerts': profile.receive_email_alerts,
            })
            context['password_form'] = CustomPasswordChangeForm(user=user)
            context['show_profile_settings'] = True
    context.update({
        'active_tab': tab,
        'show_documents': True,
        'show_device_management': True,
        'show_notifications': True,
    })
    return render(request, 'core/staff_dashboard.html', context)

@access_granted_required
def staff_dashboard(request):
    if request.user.role != 'STAFF':
        messages.error(request, "Access denied. You don't have permission to access this page.")
        return redirect('core:login')

    tab = request.GET.get('tab', 'dashboard')
    ctx = _staff_base_context(request.user)

    # Ensure profile forms exist when tab=profile
    if tab == 'profile':
        profile = getattr(request.user, 'profile', None)
        if profile:
            ctx['profile_form'] = ProfileUpdateForm(initial={
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'department': profile.department,
                'position': profile.position,
                'email': request.user.email,
                'phone': profile.phone,
                'show_risk_alerts': profile.show_risk_alerts,
                'auto_logout': profile.auto_logout,
                'receive_email_alerts': profile.receive_email_alerts,
            })
            ctx['password_form'] = CustomPasswordChangeForm(user=request.user)
            ctx['show_profile_settings'] = True

    ctx.update({
        'active_tab': tab,
        'show_documents': True,
        'show_device_management': True,
        'show_notifications': True,
    })
    return render(request, 'core/staff_dashboard.html', ctx)

@access_granted_required
def admin_dashboard(request):
    if request.user.role != 'ADMIN':
        messages.error(request, "Access denied. You don't have permission to access this page.")
        return redirect('core:login')

    request.user.last_activity = timezone.now()
    request.user.save(update_fields=['last_activity'])

    tab = request.GET.get('tab', 'dashboard')
    ctx = _admin_base_context(request.user)

    # Ensure profile forms exist when tab=profile
    if tab == 'profile':
        profile = getattr(request.user, 'profile', None)
        if profile:
            ctx['profile_form'] = ProfileUpdateForm(initial={
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'department': profile.department,
                'position': profile.position,
                'email': request.user.email,
                'phone': profile.phone,
                'show_risk_alerts': profile.show_risk_alerts,
                'auto_logout': profile.auto_logout,
                'receive_email_alerts': profile.receive_email_alerts,
            })
            ctx['password_form'] = CustomPasswordChangeForm(user=request.user)
            ctx['show_profile_settings'] = True

    ctx.update({
        'active_tab': tab,
        'show_documents': True,
        'show_audit_logs': True,
        'show_device_management': True,
        'show_notifications': True,
    })
    return render(request, 'core/admin_dashboard.html', ctx)

@login_required
@user_passes_test(is_admin)
def admin_users(request):
    ctx = _admin_base_context(request.user)
    ctx.update({'show_user_management': True, 'active_tab': 'users'})
    return render(request, 'core/admin_dashboard.html', ctx)

# -------------------- Documents --------------------
@login_required
def document_list(request):
    user = request.user
    if not hasattr(user, 'profile'):
        request.session['complete_profile_user'] = user.id
        return redirect('core:complete_profile')

    # Start from base context
    if user.role == 'ADMIN':
        ctx = _admin_base_context(user)
        documents = Document.objects.filter(deleted=False)
    else:
        ctx = _staff_base_context(user)
        documents = ctx['documents']  # already filtered for staff

    query = request.GET.get('q', '')
    if query:
        documents = documents.filter(Q(title__icontains=query) | Q(description__icontains=query))

    ctx.update({
        'documents': documents,
        'query': query,
        'show_documents': True,
        'active_tab': 'documents'
    })

    return render(request, _role_template(user), ctx)

@login_required
@user_passes_test(is_admin)
def document_upload(request):
    ctx = _admin_base_context(request.user)
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.uploaded_by = request.user

            file_field = request.FILES.get('file')
            if not file_field:
                form.add_error('file', 'File is required.')
            else:
                file_data = file_field.read()
                encrypted_data = encrypt_file(file_data, request.user)

                doc.encrypted_file = encrypted_data
                doc.original_filename = file_field.name
                doc.file_type = file_field.content_type
                doc.file_size = file_field.size
                doc.encryption_key = get_fernet_key(request.user)

                existing = Document.objects.filter(
                    title=doc.title,
                    department=doc.department,
                    deleted=False
                ).order_by('-version').first()

                if existing:
                    doc.version = existing.version + 1
                    existing.deleted = True
                    existing.save()

                doc.save()
                messages.success(request, 'Document uploaded successfully.')
                return _redirect_to_tab(request, 'documents')
        else:
            logger.warning(f"Document upload form invalid: {form.errors}")
            messages.error(request, 'There was an error uploading the document. Please check the form and try again.')
    else:
        form = DocumentUploadForm()

    if request.method == 'POST' and not form.is_valid():
        messages.error(request, 'Document was not saved. Please check all required fields and try again.')
        logger.error(f"Document upload failed. POST data: {request.POST}, FILES: {request.FILES}, errors: {form.errors}")

    ctx.update({'form': form, 'show_document_upload': True, 'active_tab': 'upload'})
    return render(request, 'core/admin_dashboard.html', ctx)

@login_required
def document_download(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, deleted=False)
    user = request.user
    if not hasattr(user, 'profile'):
        request.session['complete_profile_user'] = user.id
        return redirect('core:complete_profile')

    if user.role != 'ADMIN':
        if doc.access_level == 'PRIVATE' and doc.uploaded_by != user:
            return HttpResponseForbidden("You don't have permission to access this document")
        if doc.access_level == 'DEPT' and (not hasattr(user, 'profile') or (doc.department != user.profile.department and doc.department != 'ALL')):
            return HttpResponseForbidden("You don't have permission to access this document")
        if doc.required_access_level < user.profile.access_level:
            return HttpResponseForbidden("You don't have permission to access this document")

    try:
        decrypted_data = decrypt_file(doc.encrypted_file, doc.uploaded_by)
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{doc.original_filename}"'
        DocumentAccessLog.objects.create(
            user=user, document=doc, was_successful=True, ip_address=get_client_ip(request)
        )
        return response
    except (IOError, InvalidToken) as e:
        logger.error(f"Document download failed: {str(e)}")
        return HttpResponseBadRequest("Failed to download document")

@login_required
@user_passes_test(is_admin)
def document_edit(request, doc_id):
    existing = get_object_or_404(Document, id=doc_id, deleted=False)

    if request.user.role != 'ADMIN' and existing.required_access_level < request.user.profile.access_level:
        return HttpResponseForbidden("You don't have permission to edit this document")

    if request.method == "POST":
        form = DocumentEditForm(request.POST, request.FILES)
        if form.is_valid():
            new_doc = form.save(commit=False)
            new_doc.uploaded_by = request.user

            if request.FILES.get("file"):
                file_data = request.FILES["file"].read()
                encrypted_data = encrypt_file(file_data, request.user)
                new_doc.encrypted_file = encrypted_data
                new_doc.original_filename = request.FILES["file"].name
                new_doc.file_type = request.FILES["file"].content_type
                new_doc.file_size = request.FILES["file"].size
                new_doc.encryption_key = get_fernet_key(request.user)
            else:
                new_doc.encrypted_file = existing.encrypted_file
                new_doc.original_filename = existing.original_filename
                new_doc.file_type = existing.file_type
                new_doc.file_size = existing.file_size
                new_doc.encryption_key = existing.encryption_key

            new_doc.version = existing.version + 1
            new_doc.parent = existing
            existing.deleted = True
            existing.save()
            new_doc.save()

            DocumentAccessLog.objects.create(
                user=request.user, document=new_doc, access_type="EDIT",
                was_successful=True, ip_address=get_client_ip(request),
            )

            return _redirect_to_tab(request, 'documents')

    form = DocumentEditForm(instance=existing, initial={"department": existing.department})

    ctx = _admin_base_context(request.user)
    documents = Document.objects.filter(deleted=False)
    ctx.update({
        "documents": documents,
        "query": "",
        "show_documents": True,
        "edit_form": form,
        "edit_document": existing,
        "show_document_edit": True,
        "active_tab": "documents",
    })

    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        modal_html = render_to_string("core/partials/document_edit_modal.html", ctx, request=request)
        return HttpResponse(modal_html)

    return render(request, "core/admin_dashboard.html", ctx)

@login_required
@user_passes_test(is_admin)
def document_access_logs(request):
    ctx = _admin_base_context(request.user)
    logs = DocumentAccessLog.objects.all().order_by('-timestamp')[:100]
    ctx.update({'logs': logs, 'show_document_logs': True, 'active_tab': 'documents'})
    return render(request, 'core/admin_dashboard.html', ctx)

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
    return _redirect_to_tab(request, 'documents')

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

# -------------------- Profile --------------------
@login_required
def profile_settings(request):
    """
    Kept for direct navigation, but dashboards now also populate forms
    when ?tab=profile is used.
    """
    user = request.user
    if not hasattr(user, 'profile'):
        request.session['complete_profile_user'] = user.id
        return redirect('core:complete_profile')
    profile = user.profile

    # Base context per role
    ctx = _admin_base_context(user) if user.role == 'ADMIN' else _staff_base_context(user)

    form = ProfileUpdateForm(initial={
        'first_name': user.first_name,
        'last_name': user.last_name,
        'department': profile.department,
        'position': profile.position,
        'email': user.email,
        'phone': profile.phone,
        'show_risk_alerts': profile.show_risk_alerts,
        'auto_logout': profile.auto_logout,
        'receive_email_alerts': profile.receive_email_alerts
    })

    ctx.update({
        'profile': profile,
        'profile_form': form,
        'password_form': CustomPasswordChangeForm(user=user),
        'face_form': FaceEnrollForm(),
        'show_profile_settings': True,
        'active_tab': 'profile',
    })
    return render(request, _role_template(user), ctx)

@login_required
@require_POST
def update_profile(request):
    user = request.user
    if not hasattr(user, 'profile'):
        request.session['complete_profile_user'] = user.id
        return redirect('core:complete_profile')
    profile = user.profile

    form = ProfileUpdateForm(request.POST, request.FILES, instance=profile)
    if form.is_valid():
        form.save()
        if form.cleaned_data['email'] != user.email:
            token = Fernet.generate_key().decode()
            expiration = timezone.now() + timedelta(hours=24)
            request.session['pending_email_update'] = form.cleaned_data['email']
            user.email_verification_token = token
            user.email_verification_expiration = expiration
            user.save()

            verify_url = request.build_absolute_uri(reverse('core:verify_email_update', kwargs={'token': token}))
            subject = 'Verify Email Change'
            message = render_to_string('emails/verify_email_update.html', {
                'user': user, 'verify_link': verify_url, 'new_email': form.cleaned_data['email']
            })
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [form.cleaned_data['email']], fail_silently=True)

            messages.info(request, f"Verification email sent to {form.cleaned_data['email']}. Please verify to complete the email change.")

        AuditLog.objects.create(
            user=user, action='PROFILE_UPDATE', details='Profile information updated',
            ip_address=get_client_ip(request)
        )
        Notification.objects.create(
            user=user, message="Your profile information was updated.", notification_type='INFO'
        )

    return _redirect_to_tab(request, 'profile')

@login_required
@require_POST
def change_password(request):
    user = request.user
    form = CustomPasswordChangeForm(user, request.POST)
    if form.is_valid():
        form.save()
        AuditLog.objects.create(
            user=user, action='PASSWORD_CHANGE', details='Password changed',
            ip_address=get_client_ip(request)
        )
        Notification.objects.create(
            user=user, message="Your password was changed successfully.", notification_type='INFO', action_required=False
        )
        messages.success(request, 'Password changed successfully.')
    else:
        messages.error(request, 'Password change failed.')
    return _redirect_to_tab(request, 'profile')

# -------------------- Devices --------------------
@login_required
def manage_devices(request):
    user = request.user
    ctx = _admin_base_context(user) if user.role == 'ADMIN' else _staff_base_context(user)
    ctx.update({'show_device_management': True, 'active_tab': 'devices'})
    return render(request, _role_template(user), ctx)

@login_required
@require_POST
def trust_device(request, device_id):
    device = get_object_or_404(DeviceFingerprint, id=device_id, user=request.user)
    device.mark_as_trusted()
    request.session['trusted_device'] = device.device_id
    AuditLog.objects.create(
        user=request.user, action='DEVICE_TRUST', details=f'Device marked as trusted: {device}',
        ip_address=get_client_ip(request)
    )
    messages.success(request, f'Device "{device}" has been marked as trusted.')
    Notification.objects.create(
        user=request.user, message=f'Device "{device}" has been marked as trusted.',
        notification_type='DEVICE', action_required=False
    )
    return _redirect_to_tab(request, 'devices')

@login_required
@require_POST
def remove_device(request, device_id):
    device = get_object_or_404(DeviceFingerprint, id=device_id, user=request.user)
    device_name = str(device)
    # remove trusted marker from session before deletion to compare id safely
    if request.session.get('trusted_device') == device.device_id:
        del request.session['trusted_device']
    device.delete()
    AuditLog.objects.create(
        user=request.user, action='DEVICE_REMOVE', details=f'Device removed: {device_name}',
        ip_address=get_client_ip(request)
    )
    messages.success(request, f'Device "{device_name}" has been removed.')
    Notification.objects.create(
        user=request.user, message=f'Device "{device_name}" has been removed from your account.',
        notification_type='DEVICE', action_required=False
    )
    return _redirect_to_tab(request, 'devices')

@login_required
@require_POST
def dismiss_device_notification(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    trust_device_flag = request.POST.get('trust_device') == 'true'
    device_id = notification.metadata.get('device_id')
    if trust_device_flag and device_id:
        try:
            device = DeviceFingerprint.objects.get(device_id=device_id, user=request.user)
            device.mark_as_trusted()
            request.session['trusted_device'] = device_id
            messages.success(request, 'Device has been marked as trusted.')
        except DeviceFingerprint.DoesNotExist:
            pass
    notification.read = True
    notification.save()

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'status': 'success'})
    return _redirect_to_tab(request, 'notifications')

# -------------------- Notifications --------------------
@login_required
def notifications_view(request):
    user = request.user
    if user.role == 'ADMIN':
        ctx = _admin_base_context(user)
    else:
        ctx = _staff_base_context(user)

    notifications = Notification.objects.filter(user=user, read=False).order_by('-created_at')

    if request.GET.get('ajax'):
        return JsonResponse({'unread': notifications.filter(read=False).count()})

    ctx.update({'notifications': notifications, 'show_notifications': True, 'active_tab': 'notifications'})
    return render(request, _role_template(user), ctx)

@login_required
@require_POST
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.read = True
    notification.save()
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'status': 'success'})
    return _redirect_to_tab(request, 'notifications')

@login_required
@require_POST
def mark_all_notifications_read(request):
    Notification.objects.filter(user=request.user, read=False).update(read=True)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'status': 'success'})
    return _redirect_to_tab(request, 'notifications')

# -------------------- Policy & Admin Actions --------------------
@login_required
@user_passes_test(is_admin)
def policy_editor(request):
    policy = RiskPolicy.objects.filter(is_active=True).first()
    if request.method == 'POST':
        form = RiskPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            new_policy = form.save(commit=False)
            if policy:
                policy.is_active = False
                policy.save()
            new_policy.is_active = True
            new_policy.save()
            return redirect('core:admin_dashboard')
    else:
        form = RiskPolicyForm(instance=policy)

    ctx = _admin_base_context(request.user)
    ctx.update({'form': form, 'show_policy_editor': True, 'active_tab': 'dashboard'})
    return render(request, 'core/admin_dashboard.html', ctx)

@login_required
@user_passes_test(is_admin)
def audit_logs(request):
    ctx = _admin_base_context(request.user)
    ctx.update({'show_audit_logs': True, 'active_tab': 'audit'})
    return render(request, 'core/admin_dashboard.html', ctx)

@login_required
@user_passes_test(is_admin)
def export_audit_logs(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'

    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action = request.GET.get('action')
    user_id = request.GET.get('user_id')

    logs = AuditLog.objects.all().order_by('-timestamp')

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

@login_required
@user_passes_test(is_admin)
@require_POST
def lock_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if (user.role == 'ADMIN' or user.is_superuser) and not request.user.is_superuser:
        messages.error(request, "You don't have permission to lock another admin.")
        return redirect('core:admin_dashboard')
    user.is_active = False
    user.save()
    AuditLog.objects.create(
        user=request.user,
        affected_user=user,
        action='ACCOUNT_LOCK',
        details=f'Account locked for {user.username}',
        ip_address=get_client_ip(request)
    )
    Notification.objects.create(
        user=user,
        message="Your account has been locked by an administrator.",
        notification_type='WARNING',
        action_required=True
    )
    return redirect('core:admin_dashboard')

@login_required
@user_passes_test(is_admin)
@require_POST
def unlock_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if (user.role == 'ADMIN' or user.is_superuser) and not request.user.is_superuser:
        messages.error(request, "You don't have permission to unlock this admin.")
        return redirect('core:admin_dashboard')
    user.is_active = True
    user.save()
    AuditLog.objects.create(
        user=request.user,
        affected_user=user,
        action='ACCOUNT_UNLOCK',
        details=f'Account unlocked for {user.username}',
        ip_address=get_client_ip(request)
    )
    Notification.objects.create(
        user=user,
        message="Your account has been unlocked by an administrator.",
        notification_type='INFO',
        action_required=False
    )
    return redirect('core:admin_dashboard')

@login_required
@user_passes_test(is_admin)
@require_POST
def set_access_level(request, user_id, level):
    target = get_object_or_404(User, id=user_id)
    if not hasattr(target, 'profile'):
        messages.error(request, 'User profile not found.')
        return redirect('core:admin_dashboard')
    try:
        level = int(level)
    except (TypeError, ValueError):
        return HttpResponseBadRequest('Invalid access level')
    if level not in [1, 2, 3]:
        return HttpResponseBadRequest('Invalid access level')
    target.profile.access_level = level
    target.profile.save(update_fields=['access_level'])
    messages.success(request, f'Updated access level for {target.username}.')
    return redirect('core:admin_dashboard')

@login_required
@user_passes_test(is_admin)
@require_POST
def allow_high_risk_session(request, session_id):
    session = get_object_or_404(UserSession, id=session_id)
    session.access_granted = True
    session.flagged_reason = ''
    session.save(update_fields=['access_granted', 'flagged_reason'])

    session.user.admin_high_risk_override = True
    session.user.save(update_fields=["admin_high_risk_override"])

    AuditLog.objects.create(
        user=request.user,
        affected_user=session.user,
        action='ACCESS_GRANTED',
        details=f'Admin override for session {session.id}',
        ip_address=get_client_ip(request)
    )

    messages.success(request, 'Session access granted.')
    return redirect('core:admin_dashboard')

# -------------------- Password Reset & Email Update --------------------
def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.get(email=email)
            token = Fernet.generate_key().decode()
            expiration = timezone.now() + timedelta(hours=24)
            user.email_verification_token = token
            user.email_verification_expiration = expiration
            user.save()

            reset_url = request.build_absolute_uri(
                reverse('core:password_reset_confirm', kwargs={'user_id': user.id, 'token': token})
            )

            subject = 'Password Reset Request'
            message = render_to_string('emails/password_reset.html', {
                'user': user, 'reset_link': reset_url
            })

            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
            return render(request, 'core/password_reset_done.html')
    else:
        form = PasswordResetForm()
    return render(request, 'core/password_reset.html', {'form': form})

def password_reset_confirm(request, user_id, token):
    user = get_object_or_404(User, id=user_id)

    if user.email_verification_token != token or user.email_verification_expiration < timezone.now():
        return render(request, 'core/login.html', {'error': 'Password reset link is invalid or has expired.'})

    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            user.set_password(new_password)
            user.email_verification_token = None
            user.email_verification_expiration = None
            user.save()

            AuditLog.objects.create(
                user=user, action='PASSWORD_RESET', details='Password reset via email link',
                ip_address=get_client_ip(request)
            )
            Notification.objects.create(
                user=user, message="Your password was reset via email link.", notification_type='INFO', action_required=False
            )
            return redirect('core:login')
    else:
        form = PasswordResetConfirmForm()

    return render(request, 'core/password_reset_confirm.html', {'form': form})

# -------------------- Access Denied & Email Verification --------------------
def access_denied(request):
    reason = request.GET.get('reason', 'Access denied due to security policy')
    
    # Log out the user to prevent any further access attempts
    if request.user.is_authenticated:
        django_logout(request)
    
    # Add the reason as a message and redirect to login
    messages.error(request, reason)
    return redirect('core:login')

def verify_email_update(request, token):
    user = get_object_or_404(User, email_verification_token=token)

    if user.email_verification_expiration < timezone.now():
        return render(request, 'core/login.html', {'error': 'Email verification link has expired.'})

    new_email = request.session.get('pending_email_update')
    if not new_email:
        return render(request, 'core/login.html', {'error': 'Email update session has expired.'})

    old_email = user.email
    user.email = new_email
    user.email_verification_token = None
    user.email_verification_expiration = None
    user.save()

    AuditLog.objects.create(
        user=user, action='EMAIL_CHANGE', details=f'Email changed from {old_email} to {new_email}',
        ip_address=get_client_ip(request)
    )

    request.session.pop('pending_email_update', None)
    messages.success(request, 'Your email has been successfully updated.')

    if request.user.is_authenticated:
        return _redirect_to_tab(request, 'profile')
    return redirect('core:login')
