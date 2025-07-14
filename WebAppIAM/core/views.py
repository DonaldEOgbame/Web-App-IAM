# views.py
import json
import logging
import csv
import hashlib
from datetime import datetime, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
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
    UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog, Notification
)
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
    DocumentUploadForm, ProfileCompletionForm
)

logger = logging.getLogger(__name__)

# --- Encryption Utilities ---
def get_fernet_key():
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

def encrypt_file(data):
    f = Fernet(get_fernet_key())
    return f.encrypt(data)

def decrypt_file(encrypted_data):
    f = Fernet(get_fernet_key())
    return f.decrypt(encrypted_data)

# --- Utility Functions ---
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

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

# --- Admin Check ---
def is_admin(user):
    return user.role == 'ADMIN'

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
            UserProfile.objects.create(
                user=user,
                full_name=form.cleaned_data['full_name'],
                department=form.cleaned_data['department'],
                position=form.cleaned_data['position']
            )
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
                    return redirect('core:student_dashboard' if user.role == 'STUDENT' else 'core:admin_dashboard')
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
        user.FINGERPRINT_ENROLLED = True
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
            auth_login(request, user)
            dashboard_url = 'admin_dashboard' if user.role == 'ADMIN' else 'student_dashboard'
            return JsonResponse({'status': 'success', 'redirect': reverse(f'core:{dashboard_url}')})
        
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"WebAuthn registration failed: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

# --- Authentication Views ---
def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if not user.is_active:
                    return render(request, 'core/login.html', {
                        'form': form,
                        'error': 'Account is not activated yet.'
                    })
                    
                # Check if biometrics are enrolled
                has_biometrics = (
                    WebAuthnCredential.objects.filter(user=user).exists() or
                    user.face_data is not None
                )
                
                if not has_biometrics:
                    # Redirect to biometric enrollment
                    request.session['pending_user_id'] = user.id
                    return redirect('core:register_biometrics')
                
                auth_login(request, user)
                
                # Redirect based on user role
                if user.role == 'ADMIN':
                    return redirect('core:admin_dashboard')
                return redirect('core:student_dashboard')
            else:
                return render(request, 'core/login.html', {
                    'form': form,
                    'error': 'Invalid email or password.'
                })
    else:
        form = LoginForm()
    
    return render(request, 'core/login.html', {'form': form})

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
            auth_login(request, user)
            dashboard_url = 'admin_dashboard' if user.role == 'ADMIN' else 'student_dashboard'
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
    
    # Behavior analysis
    behavior_profile = user.userbehaviorprofile
    current_time = timezone.now().time()
    time_anomaly = 0
    device_anomaly = 0
    fingerprint_anomaly = 0
    
    if behavior_profile.typical_login_time:
        time_diff = abs((datetime.combine(timezone.now().date(), current_time) - 
                        datetime.combine(timezone.now().date(), behavior_profile.typical_login_time)).total_seconds())
        time_anomaly = min(time_diff / 3600, 1)
    
    if behavior_profile.typical_device and behavior_profile.typical_device != session.user_agent:
        device_anomaly = 1
    
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
        if session.risk_level == 'HIGH' and active_policy.high_risk_action == 'DENY':
            session.access_granted = False
            session.flagged_reason = "High risk session"
        elif session.risk_level == 'HIGH' and active_policy.high_risk_action == 'CHALLENGE':
            session.access_granted = True
            Notification.objects.create(
                user=user,
                message='High-risk login detected. Please verify your identity.',
                action_required=True
            )
        else:
            session.access_granted = True
    else:
        session.access_granted = session.risk_level != 'HIGH'
    
    session.save()
    
    # Update behavior profile
    if session.access_granted:
        if not behavior_profile.typical_login_time:
            behavior_profile.typical_login_time = current_time
        if not behavior_profile.typical_device:
            behavior_profile.typical_device = session.user_agent
        if not behavior_profile.typical_device_fingerprint:
            behavior_profile.typical_device_fingerprint = session.device_fingerprint
        behavior_profile.save()
    
    return session

def logout(request):
    if request.user.is_authenticated:
        session_key = request.session.session_key
        try:
            session = UserSession.objects.get(session_key=session_key)
            session.logout_time = timezone.now()
            session.save()
        except UserSession.DoesNotExist:
            pass
        
        request.user.last_activity = timezone.now()
        request.user.save()
        auth_logout(request)
    
    return redirect('core:login')

# --- Dashboard Views ---
@login_required
def dashboard(request):
    # Profile completion gate
    if not hasattr(request.user, 'userprofile'):
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
    
    return render(request, 'core/student_dashboard.html', context)

@login_required
def student_dashboard(request):
    # Ensure biometric enrollment and verification
    if not request.user.has_biometrics:
        return redirect('core:register_biometrics')
    
    context = {
        'resources': Document.objects.filter(is_public=True),
        'notifications': Notification.objects.filter(user=request.user, is_read=False),
        'sessions': UserSession.objects.filter(user=request.user).order_by('-created_at')[:5]
    }
    return render(request, 'core/student_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # Ensure biometric enrollment and verification
    if not request.user.has_biometrics:
        return redirect('core:register_biometrics')
    
    context = {
        'pending_users': User.objects.filter(is_active=False),
        'recent_logins': UserSession.objects.all().order_by('-created_at')[:10],
        'risk_alerts': UserBehaviorProfile.objects.filter(risk_score__gte=settings.HIGH_RISK_THRESHOLD),
        'document_access': DocumentAccessLog.objects.all().order_by('-timestamp')[:10]
    }
    return render(request, 'core/admin_dashboard.html', context)

# --- Document Vault Views ---
@login_required
def document_list(request):
    user = request.user
    documents = Document.objects.filter(deleted=False)
    
    # Filter by access level
    if user.role != 'ADMIN':
        documents = documents.filter(
            Q(access_level='PUBLIC') |
            Q(access_level='DEPARTMENT', department=user.userprofile.department)
        )
    
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
    return render(request, 'core/student_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def document_upload(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.uploaded_by = request.user
            
            # Encrypt file
            file_data = request.FILES['file'].read()
            encrypted_data = encrypt_file(file_data)
            
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
    
    # Check access permissions
    if user.role != 'ADMIN':
        if doc.access_level == 'PRIVATE' and doc.uploaded_by != user:
            return HttpResponseForbidden("You don't have permission to access this document")
        if doc.access_level == 'DEPARTMENT' and doc.department != user.userprofile.department:
            return HttpResponseForbidden("You don't have permission to access this document")
    
    # Check session risk
    current_session = UserSession.objects.filter(
        user=user, 
        logout_time__isnull=True
    ).order_by('-login_time').first()
    
    if not current_session or not current_session.access_granted or current_session.risk_level != 'LOW':
        DocumentAccessLog.objects.create(
            user=user,
            document=doc,
            was_blocked=True,
            reason="High-risk session",
            ip_address=get_client_ip(request)
        )
        return redirect('core:access_denied')
    
    if doc.is_expired():
        DocumentAccessLog.objects.create(
            user=user,
            document=doc,
            was_blocked=True,
            reason="Document expired",
            ip_address=get_client_ip(request)
        )
        return redirect('core:access_denied')
    
    try:
        # Decrypt file
        decrypted_data = decrypt_file(doc.file.read())
        
        # Create response
        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{doc.original_filename}"'
        
        # Log access
        DocumentAccessLog.objects.create(
            user=user,
            document=doc,
            was_blocked=False,
            ip_address=get_client_ip(request)
        )
        
        return response
    except (IOError, InvalidToken) as e:
        logger.error(f"Document download failed: {str(e)}")
        return HttpResponseBadRequest("Failed to download document")

@login_required
@user_passes_test(is_admin)
@require_POST
def restore_document_version(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, deleted=True)
    
    # Find current active version
    current = Document.objects.filter(
        title=doc.title,
        category=doc.category,
        department=doc.department,
        deleted=False
    ).first()
    
    if current:
        current.deleted = True
        current.save()
    
    doc.deleted = False
    doc.save()
    
    AuditLog.objects.create(
        user=request.user,
        action='DOCUMENT_RESTORE',
        details=f'Restored version {doc.version} of "{doc.title}"',
        ip_address=get_client_ip(request)
    )
    return redirect('core:document_access_logs')

@login_required
@user_passes_test(is_admin)
def document_access_logs(request):
    logs = DocumentAccessLog.objects.all().order_by('-timestamp')[:100]
    return render(request, 'core/admin_dashboard.html', {
        'logs': logs,
        'show_document_logs': True
    })

# --- Document Vault Enhancements ---
@login_required
def document_versions(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)
    versions = Document.objects.filter(
        title=document.title,
        category=document.category,
        department=document.department
    ).order_by('-version')

    context = {
        'document': document,
        'versions': versions,
        'show_versions': True
    }
    return render(request, 'core/document_versions.html', context)

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
        decrypted_data = decrypt_file(document.file.read())
        checksum = hashlib.sha256(decrypted_data).hexdigest()
        return JsonResponse({'status': 'success', 'checksum': checksum})
    except InvalidToken:
        return JsonResponse({'status': 'error', 'message': 'Checksum validation failed'}, status=400)

# --- Profile Management ---
@login_required
def profile_settings(request):
    user = request.user
    profile = user.userprofile
    
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
                template = 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/student_dashboard.html'
                return render(request, template, context)
        # Handle profile update
        else:
            profile.full_name = request.POST.get('full_name', profile.full_name)
            profile.department = request.POST.get('department', profile.department)
            profile.position = request.POST.get('position', profile.position)
            profile.save()
            return redirect('core:profile_settings')
    
    context = {
        'profile': profile,
        'password_form': CustomPasswordChangeForm(user=user),
        'face_form': FaceEnrollForm(),
        'user': user,
        'show_profile_settings': True
    }
    
    template = 'core/admin_dashboard.html' if user.role == 'ADMIN' else 'core/student_dashboard.html'
    return render(request, template, context)

# --- Notification System ---
@login_required
def notifications_view(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    context = {
        'notifications': notifications,
        'show_notifications': True
    }
    
    if request.user.role == 'ADMIN':
        return render(request, 'core/admin_dashboard.html', context)
    return render(request, 'core/student_dashboard.html', context)

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
    logs = AuditLog.objects.all().order_by('-timestamp')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'IP Address', 'Details'])
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'System',
            log.action,
            log.ip_address,
            log.details[:200]  # Truncate long details
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
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        
        if user:
            token = Fernet.generate_key().decode()
            request.session[f'pwd_reset_{user.id}'] = token
            
            reset_url = request.build_absolute_uri(
                reverse('core:password_reset_confirm', kwargs={
                    'user_id': user.id,
                    'token': token
                })
            )
            
            subject = 'Password Reset Request'
            message = render_to_string('emails/password_reset.html', {
                'user': user,
                'reset_link': reset_url
            })
            plain_message = render_to_string('emails/password_reset.txt', {
                'user': user,
                'reset_link': reset_url
            })
            
            send_mail(
                subject,
                plain_message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                html_message=message,
                fail_silently=True
            )
            return render(request, 'core/login.html', {'message': 'Password reset instructions have been sent to your email.'})
    
    return render(request, 'core/login.html', {'show_password_reset': True})

def password_reset_confirm(request, user_id, token):
    session_token = request.session.get(f'pwd_reset_{user_id}')
    
    if not session_token or session_token != token:
        return render(request, 'core/login.html', {'error': 'Invalid password reset link.'})
    
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user, request.POST)
        if form.is_valid():
            form.save()
            del request.session[f'pwd_reset_{user_id}']
            return render(request, 'core/login.html', {'message': 'Password has been reset successfully. Please login.'})
    else:
        form = CustomPasswordChangeForm(user)
    
    return render(request, 'core/login.html', {'form': form, 'show_password_reset_confirm': True})

# --- Access Denied View ---
def access_denied(request):
    reason = request.GET.get('reason', 'Access denied due to security policy')
    context = {
        'reason': reason,
        'show_access_denied': True
    }
    
    if request.user.is_authenticated:
        template = 'core/admin_dashboard.html' if request.user.role == 'ADMIN' else 'core/student_dashboard.html'
        return render(request, template, context)
    return render(request, 'core/login.html', context)