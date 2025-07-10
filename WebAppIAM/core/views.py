import json
import logging
from datetime import datetime, time
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from .models import (
    User, UserBehaviorProfile, WebAuthnCredential, 
    UserSession, RiskPolicy, AuditLog
)
from .webauthn_utils import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from .face_api import verify_face, enroll_face
from .risk_engine import calculate_risk_score, analyze_behavior_anomaly

logger = logging.getLogger(__name__)

def is_admin(user):
    return user.role == 'ADMIN'

# Registration Views
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        role = request.POST.get('role', 'USER')
        
        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username already exists'})
        
        user = User.objects.create_user(username=username, password=password, role=role)
        UserBehaviorProfile.objects.create(user=user)
        
        # Store user ID in session for multi-step registration
        request.session['registration_user_id'] = user.id
        return redirect('register_biometrics')
    
    return render(request, 'register.html')

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
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is None:
            AuditLog.objects.create(
                user=None,
                action='LOGIN_ATTEMPT',
                details=f'Failed login attempt for {username}',
                ip_address=get_client_ip(request),
                metadata={'reason': 'Invalid credentials'}
            )
            return render(request, 'login.html', {'error': 'Invalid credentials'})
        
        # Create a session record (not authenticated yet - waiting for biometrics)
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
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
            return redirect('verify_biometrics')
        else:
            # If no biometrics, proceed with risk evaluation
            session = finalize_authentication(request, session)
            return redirect('dashboard')
    
    return render(request, 'login.html')

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

@login_required
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
    
    # Simple behavior anomaly detection (will be replaced with ML model)
    time_anomaly = 0
    if typical_login_start:
        time_diff = abs((datetime.combine(datetime.today(), current_time) - 
                        datetime.combine(datetime.today(), typical_login_start)).total_seconds())
        time_anomaly = min(time_diff / 3600, 1)  # Normalize to 0-1 range
    
    device_anomaly = 0
    if behavior_profile.typical_device and behavior_profile.typical_device != session.user_agent:
        device_anomaly = 1
    
    # Calculate behavior anomaly score (simple average for now)
    session.behavior_anomaly_score = (time_anomaly + device_anomaly) / 2
    
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
    else:
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
    
    return session

# Dashboard Views
@login_required
def dashboard(request):
    user = request.user
    sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:10]
    
    context = {
        'user': user,
        'sessions': sessions,
        'face_enrolled': user.FACE_ENROLLED,
        'fingerprint_enrolled': user.FINGERPRINT_ENROLLED,
    }
    return render(request, 'dashboard.html', context)

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
    
    auth_logout(request)
    return redirect('login')