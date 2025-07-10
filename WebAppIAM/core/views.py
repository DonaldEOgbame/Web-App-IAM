# --- Utility: Admin check ---
def is_admin(user):
    return user.role == 'ADMIN'

from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required, user_passes_test
# --- Admin: Restore Previous Document Version ---
@login_required
@user_passes_test(is_admin)
@require_POST
def restore_document_version(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, deleted=True)
    # Find the current active version (if any)
    current = Document.objects.filter(title=doc.title, category=doc.category, department=doc.department, deleted=False).order_by('-version').first()
    if current:
        current.deleted = True
        current.save()
    doc.deleted = False
    doc.save()
    AuditLog.objects.create(user=request.user, action='DOCUMENT_RESTORE', details=f'Restored version v{doc.version} of "{doc.title}"', ip_address=get_client_ip(request))
    return redirect('core:document_access_logs')
import json
import logging
from datetime import datetime, time
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from .models import (
    User, UserBehaviorProfile, WebAuthnCredential, 
    UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog
)
from .webauthn_utils import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from .face_api import verify_face, enroll_face
from .risk_engine import calculate_risk_score
from .forms import (
    RegistrationForm, LoginForm, FaceEnrollForm, FingerprintReRegisterForm, RiskPolicyForm, ReportSubmissionForm, CustomPasswordChangeForm, DocumentUploadForm
)

logger = logging.getLogger(__name__)

# Registration Views
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        role = request.POST.get('role', 'USER')
        
        if User.objects.filter(username=username).exists():
            return render(request, 'core/register.html', {'error': 'Username already exists'})
        
        user = User.objects.create_user(username=username, password=password, role=role)
        UserBehaviorProfile.objects.create(user=user)
        from .models import UserPreference
        UserPreference.objects.create(user=user)
        
        # Store user ID in session for multi-step registration
        request.session['registration_user_id'] = user.id
        return redirect('register_biometrics')
    
    return render(request, 'core/register.html')

@login_required
def register_biometrics(request):
    user = request.user
    if request.method == 'POST':
        # Handle face enrollment
        if 'face_image' in request.FILES:
            face_image = request.FILES['face_image']
            try:
                face_id = enroll_face(user, face_image)
                user.azure_face_id = face_id
                user.FACE_ENROLLED = True
                user.save()
                
                AuditLog.objects.create(
                    user=user,
                    action='FACE_ENROLL',
                    details='Face enrolled successfully',
                    ip_address=get_client_ip(request)
                )
                return JsonResponse({'status': 'success', 'message': 'Face enrolled successfully'})
            except Exception as e:
                logger.error(f"Face enrollment failed: {str(e)}")
                return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
        
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
    
    context = {
        'user': user,
        'webauthn_enabled': settings.WEBAUTHN_ENABLED,
    }
    return render(request, 'register_biometrics.html', context)

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
        user.FINGERPRINT_ENROLLED = True
        user.save()
        
        AuditLog.objects.create(
            user=user,
            action='FINGERPRINT_ENROLL',
            details='Fingerprint enrolled successfully',
            ip_address=get_client_ip(request)
        )
        
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"WebAuthn registration failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

# Authentication Views
def login(request):
    # Rate limit login attempts
    if not rate_limit(request, 'login', limit=5, window=60):
        return render(request, 'core/login.html', {'error': 'Too many login attempts. Please try again later.'})
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Ensure UserPreference exists
            from .models import UserPreference
            UserPreference.objects.get_or_create(user=user)
        if user is None:
            AuditLog.objects.create(
                user=None,
                action='LOGIN_ATTEMPT',
                details=f'Failed login attempt for {username}',
                ip_address=get_client_ip(request),
                metadata={'reason': 'Invalid credentials'}
            )
            # Optional: notify admin of repeated failed logins
            if AuditLog.objects.filter(action='LOGIN_ATTEMPT', ip_address=get_client_ip(request), timestamp__gte=timezone.now()-timezone.timedelta(hours=1)).count() > 5:
                notify_admin('Repeated Failed Logins', f'IP {get_client_ip(request)} had multiple failed logins in the past hour.')
            return render(request, 'core/login.html', {'error': 'Invalid credentials'})
        # Create a session record (not authenticated yet - waiting for biometrics)
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            device_fingerprint=request.META.get('HTTP_X_DEVICE_FINGERPRINT'),
            face_match_score=None,
            fingerprint_verified=False,
            behavior_anomaly_score=None,
            risk_score=None,
            risk_level='LOW',
            access_granted=False
        )
        request.session['pending_auth_user_id'] = user.id
        request.session['pending_auth_session_id'] = session.id
        # Check if user has biometrics enrolled
        if user.FACE_ENROLLED or user.FINGERPRINT_ENROLLED:
            return redirect('core:verify_biometrics')
        else:
            # If no biometrics, proceed with risk evaluation
            session = finalize_authentication(request, session)
            return redirect('core:dashboard')
    return render(request, 'core/login.html')

@login_required
def verify_biometrics(request):
    user = request.user
    session_id = request.session.get('pending_auth_session_id')
    
    if not session_id:
        return redirect('login')
    
    try:
        session = UserSession.objects.get(id=session_id, user=user)
    except UserSession.DoesNotExist:
        return redirect('login')
    
    if request.method == 'POST':
        # Handle face verification
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
    
    context = {
        'user': user,
        'session_id': session_id,
        'require_face': user.FACE_ENROLLED,
        'require_fingerprint': user.FINGERPRINT_ENROLLED,
        'webauthn_enabled': settings.WEBAUTHN_ENABLED,
    }
    return render(request, 'verify_biometrics.html', context)

@csrf_exempt
@require_http_methods(['POST'])
def webauthn_authentication_options(request):
    if not settings.WEBAUTHN_ENABLED:
        return JsonResponse({'error': 'WebAuthn not enabled'}, status=400)
    
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
        credential.last_used_at = datetime.now()
        credential.save()
        
        session.fingerprint_verified = True
        session.save()
        
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"WebAuthn authentication failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


import time as pytime
from django.core.mail import send_mail
from django.utils import timezone
from django.core.cache import cache
@login_required

def rate_limit(request, key_prefix, limit=5, window=60):
    key = f"rate:{key_prefix}:{request.META.get('REMOTE_ADDR')}"
    count = cache.get(key, 0)
    if count >= limit:
        return False
    cache.set(key, count + 1, timeout=window)
    return True

from django.template.loader import render_to_string
def notify_admin(subject, context):
    # Send email to admins (add ADMINS in settings)
    if hasattr(settings, 'ADMINS') and settings.ADMINS:
        emails = [email for _, email in settings.ADMINS]
        message = render_to_string('emails/admin_high_risk_alert.txt', context)
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, emails)

def finalize_authentication(request, session=None):
    if not session:
        session_id = request.session.get('pending_auth_session_id')
        if not session_id:
            return None
        session = UserSession.objects.get(id=session_id)
    
    user = session.user
    
    # Analyze behavior
    behavior_profile = user.behavior_profile
    current_time = datetime.now().time()
    typical_login_start = behavior_profile.typical_login_time
    device_fingerprint = request.META.get('HTTP_X_DEVICE_FINGERPRINT')
    session.device_fingerprint = device_fingerprint

    # Simple behavior anomaly detection (will be replaced with ML model)
    time_anomaly = 0
    if typical_login_start:
        time_diff = abs((datetime.combine(datetime.today(), current_time) - 
                        datetime.combine(datetime.today(), typical_login_start)).total_seconds())
        time_anomaly = min(time_diff / 3600, 1)  # Normalize to 0-1 range

    device_anomaly = 0
    if behavior_profile.typical_device and behavior_profile.typical_device != session.user_agent:
        device_anomaly = 1
    fingerprint_anomaly = 0
    if behavior_profile.typical_device and device_fingerprint and behavior_profile.typical_device != device_fingerprint:
        fingerprint_anomaly = 1

    # Calculate behavior anomaly score (average)
    session.behavior_anomaly_score = (time_anomaly + device_anomaly + fingerprint_anomaly) / 3
    
    # Calculate risk score
    risk_score = calculate_risk_score(
        face_match_score=session.face_match_score or 0,
        fingerprint_verified=session.fingerprint_verified,
        behavior_anomaly_score=session.behavior_anomaly_score
    )
    
    session.risk_score = risk_score
    
    # Determine risk level
    if risk_score < 0.3:
        session.risk_level = 'LOW'
    elif risk_score < 0.7:
        session.risk_level = 'MEDIUM'
    else:
        session.risk_level = 'HIGH'
    
    # Apply risk policy
    active_policy = RiskPolicy.objects.filter(is_active=True).first()
    if active_policy:
        if session.risk_level == 'HIGH' and active_policy.high_risk_action == 'DENY':
            session.access_granted = False
            session.flagged_reason = "High risk session - access denied by policy"
        elif session.risk_level == 'HIGH' and active_policy.high_risk_action == 'CHALLENGE':
            # In a real implementation, we'd trigger step-up auth
            session.access_granted = True
            session.flagged_reason = "High risk session - additional verification required"
        else:
            session.access_granted = True
    else:
        # Default policy if none is configured
        session.access_granted = session.risk_level != 'HIGH'
    
    session.save()

    # Update last activity
    user.last_activity = timezone.now()
    user.save()

    if session.access_granted:
        auth_login(request, user)
        # Update behavior profile with this login as a data point
        if not behavior_profile.typical_login_time:
            behavior_profile.typical_login_time = current_time
            behavior_profile.typical_device = session.user_agent
            behavior_profile.save()
        AuditLog.objects.create(
            user=user,
            action='LOGIN_ATTEMPT',
            details=f'Successful login with risk score {risk_score:.2f}',
            ip_address=get_client_ip(request),
            metadata={
                'risk_level': session.risk_level,
                'face_score': session.face_match_score,
                'fingerprint_verified': session.fingerprint_verified,
                'behavior_score': session.behavior_anomaly_score
            }
        )
        # Optional: notify user of high-risk login
        if session.risk_level == 'HIGH' and user.email:
            context = {
                'user': user,
                'timestamp': timezone.now(),
                'ip_address': get_client_ip(request),
            }
            message = render_to_string('emails/high_risk_login.txt', context)
            send_mail(
                'High-Risk Login Detected',
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=True
            )
    else:
        session.forced_logout = True
        session.save()
        AuditLog.objects.create(
            user=user,
            action='ACCESS_DENIED',
            details=f'Access denied due to high risk score {risk_score:.2f}',
            ip_address=get_client_ip(request),
            metadata={
                'risk_level': session.risk_level,
                'face_score': session.face_match_score,
                'fingerprint_verified': session.fingerprint_verified,
                'behavior_score': session.behavior_anomaly_score
            }
        )
        # Notify admin of repeated high-risk/failed attempts
        if AuditLog.objects.filter(user=user, action='ACCESS_DENIED', timestamp__gte=timezone.now()-timezone.timedelta(hours=1)).count() > 3:
            context = {
                'user': user,
                'timestamp': timezone.now(),
                'ip_address': get_client_ip(request),
            }
            notify_admin('Repeated High-Risk Logins', context)
    return session


# Dashboard Views
@login_required
def dashboard(request):
    user = request.user
    sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:10]
    audit_logs = AuditLog.objects.filter(user=user).order_by('-timestamp')[:20]
    context = {
        'user': user,
        'sessions': sessions,
        'face_enrolled': user.FACE_ENROLLED,
        'fingerprint_enrolled': user.FINGERPRINT_ENROLLED,
        'audit_logs': audit_logs,
    }
    return render(request, 'dashboard.html', context)

# --- User Profile Page ---
@login_required
def profile(request):
    user = request.user
    sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:10]
    downloads = DocumentAccessLog.objects.filter(user=user, was_blocked=False).order_by('-timestamp')[:10]
    context = {
        'user': user,
        'sessions': sessions,
        'downloads': downloads,
        'face_enrolled': user.FACE_ENROLLED,
        'fingerprint_enrolled': user.FINGERPRINT_ENROLLED,
    }
    return render(request, 'core/profile.html', context)

# --- User Settings Page ---
@login_required
def settings(request):
    user = request.user
    password_form = CustomPasswordChangeForm(user=user)
    face_form = FaceEnrollForm()
    fingerprint_form = FingerprintReRegisterForm()
    # Use persistent UserPreference
    preference, _ = user.preference if hasattr(user, 'preference') else (None, False)
    if not preference:
        from .models import UserPreference
        preference, _ = UserPreference.objects.get_or_create(user=user)
    show_risk_alerts = preference.show_risk_alerts
    show_face_match = preference.show_face_match
    if request.method == 'POST':
        # Restrict high-risk users from updating security settings
        session = UserSession.objects.filter(user=user).order_by('-login_time').first()
        if session and session.risk_level == 'HIGH':
            return render(request, 'core/access_denied.html', {'reason': 'High-risk users cannot update security settings.'})
        if 'old_password' in request.POST:
            password_form = CustomPasswordChangeForm(user=user, data=request.POST)
            if password_form.is_valid():
                password_form.save()
                AuditLog.objects.create(user=user, action='PASSWORD_CHANGE', details='Password changed', ip_address=get_client_ip(request))
                return redirect('core:settings')
        elif 'face_image' in request.FILES:
            face_form = FaceEnrollForm(request.POST, request.FILES)
            if face_form.is_valid():
                face_image = face_form.cleaned_data['face_image']
                try:
                    face_id = enroll_face(user, face_image)
                    user.azure_face_id = face_id
                    user.FACE_ENROLLED = True
                    user.save()
                    AuditLog.objects.create(user=user, action='FACE_ENROLL', details='Face re-enrolled', ip_address=get_client_ip(request))
                    return redirect('core:settings')
                except Exception as e:
                    face_form.add_error(None, str(e))
        elif 'show_risk_alerts' in request.POST or 'show_face_match' in request.POST:
            preference.show_risk_alerts = 'show_risk_alerts' in request.POST
            preference.show_face_match = 'show_face_match' in request.POST
            preference.save()
            return redirect('core:settings')
    context = {
        'user': user,
        'password_form': password_form,
        'face_form': face_form,
        'fingerprint_form': fingerprint_form,
        'show_risk_alerts': show_risk_alerts,
        'show_face_match': show_face_match,
    }
    return render(request, 'core/settings.html', context)

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    users = User.objects.all()
    high_risk_sessions = UserSession.objects.filter(risk_level='HIGH').order_by('-login_time')[:10]
    failed_logins = AuditLog.objects.filter(action='LOGIN_ATTEMPT', user__isnull=False).exclude(metadata__has_key='success').order_by('-timestamp')[:10]
    
    context = {
        'users': users,
        'high_risk_sessions': high_risk_sessions,
        'failed_logins': failed_logins,
        'active_policy': RiskPolicy.objects.filter(is_active=True).first(),
    }
    return render(request, 'admin_dashboard.html', context)

# Document Vault Views
@login_required
def document_list(request):
    user = request.user
    q = request.GET.get('q', '')
    category = request.GET.get('category', '')
    docs = Document.objects.filter(deleted=False)
    if user.role != 'ADMIN':
        docs = docs.filter(
            Q(access_level='USER') |
            Q(access_level='DEPT', department=user.groups.first().name if user.groups.exists() else None)
        )
    if q:
        docs = docs.filter(Q(title__icontains=q) | Q(description__icontains=q))
    if category:
        docs = docs.filter(category=category)
    docs = docs.order_by('-created_at')
    session = UserSession.objects.filter(user=user).order_by('-login_time').first()
    today = timezone.now().date()
    for doc in docs:
        doc.can_download = (
            not doc.is_expired() and session and session.access_granted and session.face_match_score is not None and session.fingerprint_verified and session.risk_level == 'LOW'
        )
        # In-app notification for expiry
        if doc.expiry_date:
            if doc.expiry_date == today:
                from .models import UserNotification
                UserNotification.objects.get_or_create(
                    user=user,
                    message=f'Document "{doc.title}" expires today.',
                    type='expiry',
                    link=f'/documents/download/{doc.id}/'
                )
            elif doc.expiry_date < today:
                from .models import UserNotification
                UserNotification.objects.get_or_create(
                    user=user,
                    message=f'Document "{doc.title}" has expired.',
                    type='expiry',
                    link=f'/documents/download/{doc.id}/'
                )
    # In-app notification for high risk
    if session and session.risk_level == 'HIGH' and user.email:
        from .models import UserNotification
        UserNotification.objects.get_or_create(
            user=user,
            message='Your recent session was flagged as HIGH RISK. Please review your account activity and contact support if this was not you.',
            type='risk',
            link='/settings/'
        )
    return render(request, 'core/document_list.html', {
        'documents': docs,
        'category_choices': Document.CATEGORY_CHOICES,
        'today': today,
    })
# --- User Notification Center ---
@login_required
def notifications(request):
    user = request.user
    notifications = user.notifications.all()
    if request.method == 'POST':
        notif_id = request.POST.get('notif_id')
        if notif_id:
            notif = user.notifications.filter(id=notif_id).first()
            if notif:
                notif.read = True
                notif.save()
    return render(request, 'core/notifications.html', {'notifications': notifications})

@login_required
@user_passes_test(lambda u: u.role == 'ADMIN')
def document_upload(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.uploaded_by = request.user
            # Versioning: if uploading a new version of an existing doc (by title/category/department), increment version
            latest = Document.objects.filter(
                title=doc.title,
                category=doc.category,
                department=doc.department,
                deleted=False
            ).order_by('-version').first()
            if latest:
                doc.version = latest.version + 1
                doc.parent = latest
                latest.deleted = True  # Soft-delete previous version
                latest.save()
            doc.save()
            return redirect('core:document_list')
    else:
        form = DocumentUploadForm()
    return render(request, 'core/document_upload.html', {'form': form})

@login_required
def document_download(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, deleted=False)
    user = request.user
    session = UserSession.objects.filter(user=user).order_by('-login_time').first()
    allowed = (
        not doc.is_expired() and session and session.access_granted and session.face_match_score is not None and session.fingerprint_verified and session.risk_level == 'LOW'
    )
    was_blocked = not allowed
    # Log every attempt
    DocumentAccessLog.objects.create(
        user=user,
        document=doc,
        face_score=session.face_match_score if session else None,
        fingerprint_status=session.fingerprint_verified if session else False,
        risk_score=session.risk_score if session else None,
        was_blocked=was_blocked,
        session=session,
        ip_address=request.META.get('REMOTE_ADDR'),
    )
    if not allowed:
        return redirect('core:document_reverify', doc_id=doc.id)
    try:
        # Serve watermarked PDF if PDF, else original file
        if doc.file.name.lower().endswith('.pdf'):
            watermarked_path = doc.get_watermarked_file()
            from django.core.files.storage import default_storage
            file_handle = default_storage.open(watermarked_path, 'rb')
            filename = doc.file.name.split('/')[-1].replace('.pdf', '_watermarked.pdf')
            from django.http import FileResponse
            return FileResponse(file_handle, as_attachment=True, filename=filename)
        else:
            from django.http import FileResponse
            return FileResponse(doc.file.open('rb'), as_attachment=True, filename=doc.file.name.split('/')[-1])
    except Exception:
        from django.http import Http404
        raise Http404('File not found')

@login_required
def document_reverify(request, doc_id):
    # Optionally trigger re-authentication/biometric flow
    return render(request, 'core/access_denied.html', {'reason': 'Biometric or risk check required for this document.'})

@login_required
@user_passes_test(lambda u: u.role == 'ADMIN')
def document_access_logs(request):
    q = request.GET.get('q', '')
    logs = DocumentAccessLog.objects.all()
    if q:
        logs = logs.filter(Q(user__username__icontains=q) | Q(document__title__icontains=q) | Q(ip_address__icontains=q))
    logs = logs.order_by('-timestamp')[:200]
    return render(request, 'core/document_access_logs.html', {'logs': logs})

# Utility functions
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def logout(request):
    session_key = request.session.session_key
    try:
        session = UserSession.objects.get(session_key=session_key)
        session.logout_time = datetime.now()
        session.save()
    except UserSession.DoesNotExist:
        pass
    # Force logout if session is flagged
    if hasattr(request, 'user') and request.user.is_authenticated:
        request.user.last_activity = timezone.now()
        request.user.save()
    auth_logout(request)
    return redirect('core:login')

# --- Biometric Management ---
@login_required
def reenroll_face(request):
    user = request.user
    if request.method == 'POST':
        form = FaceEnrollForm(request.POST, request.FILES)
        if form.is_valid():
            face_image = form.cleaned_data['face_image']
            try:
                face_id = enroll_face(user, face_image)
                user.azure_face_id = face_id
                user.FACE_ENROLLED = True
                user.save()
                AuditLog.objects.create(user=user, action='FACE_ENROLL', details='Face re-enrolled', ip_address=get_client_ip(request))
                return redirect('core:dashboard')
            except Exception as e:
                return render(request, 'core/reenroll_face.html', {'form': form, 'error': str(e)})
    else:
        form = FaceEnrollForm()
    return render(request, 'core/reenroll_face.html', {'form': form})

@login_required
def reregister_fingerprint(request):
    user = request.user
    if request.method == 'POST':
        # WebAuthn handled via JS, just mark as enrolled after successful JS
        user.FINGERPRINT_ENROLLED = True
        user.save()
        AuditLog.objects.create(user=user, action='FINGERPRINT_ENROLL', details='Fingerprint re-registered', ip_address=get_client_ip(request))
        return redirect('core:dashboard')
    form = FingerprintReRegisterForm()
    return render(request, 'core/reregister_fingerprint.html', {'form': form})

# --- Password Change ---
@login_required
def password_change(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            AuditLog.objects.create(user=request.user, action='PASSWORD_CHANGE', details='Password changed', ip_address=get_client_ip(request))
            return redirect('core:dashboard')
    else:
        form = CustomPasswordChangeForm(user=request.user)
    return render(request, 'core/password_change.html', {'form': form})

# --- Policy Editor ---
@login_required
@user_passes_test(is_admin)
def policy_editor(request):
    policy = RiskPolicy.objects.filter(is_active=True).first()
    if request.method == 'POST':
        form = RiskPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            return redirect('core:admin_dashboard')
    else:
        form = RiskPolicyForm(instance=policy)
    return render(request, 'policy_editor.html', {'form': form})

# --- Audit Logs ---
@login_required
@user_passes_test(is_admin)
def audit_logs(request):
    q = request.GET.get('q', '')
    logs = AuditLog.objects.all()
    if q:
        logs = logs.filter(details__icontains=q)
    logs = logs.order_by('-timestamp')[:100]
    return render(request, 'audit_logs.html', {'logs': logs})

@login_required
@user_passes_test(is_admin)
def export_audit_logs(request):
    import csv
    from django.http import HttpResponse
    logs = AuditLog.objects.all().order_by('-timestamp')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'IP', 'Details'])
    for log in logs:
        writer.writerow([log.timestamp, log.user, log.action, log.ip_address, log.details])
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

# --- Protected Resources ---
@login_required
def secure_document(request):
    session = UserSession.objects.filter(user=request.user).order_by('-login_time').first()
    if not session or not session.access_granted:
        return redirect('core:access_denied')
    return render(request, 'secure_document.html', {'session': session})

@login_required
def report_submission(request):
    session = UserSession.objects.filter(user=request.user).order_by('-login_time').first()
    if not session or not session.access_granted:
        return redirect('core:access_denied')
    if request.method == 'POST':
        form = ReportSubmissionForm(request.POST)
        if form.is_valid():
            # Save or process report as needed
            return redirect('core:dashboard')
    else:
        form = ReportSubmissionForm()
    return render(request, 'report_submission.html', {'form': form, 'session': session})

@login_required
def personal_data(request):
    session = UserSession.objects.filter(user=request.user).order_by('-login_time').first()
    if not session or not session.access_granted:
        return redirect('core:access_denied')
    return render(request, 'personal_data.html', {'user': request.user, 'session': session})

def access_denied(request):
    reason = request.GET.get('reason', 'Access denied due to risk or policy.')
    return render(request, 'core/access_denied.html', {'reason': reason})

def base_context(request):
    unread_notifications_count = 0
    if request.user.is_authenticated:
        unread_notifications_count = request.user.notifications.filter(read=False).count()
    return {'unread_notifications_count': unread_notifications_count}