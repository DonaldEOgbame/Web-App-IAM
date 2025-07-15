import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth import login
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseForbidden
from .emergency import EmergencyAccessProtocol
from .models import User

logger = logging.getLogger(__name__)

@login_required
@permission_required('core.manage_emergency_access', raise_exception=True)
def emergency_access_dashboard(request):
    """Emergency access dashboard for administrators"""
    context = {
        'emergency_mode': EmergencyAccessProtocol.check_emergency_mode(),
    }
    
    # Check if a token was generated
    if 'emergency_token' in request.session:
        context['emergency_token'] = request.session['emergency_token']
        context['token_username'] = request.session['token_username']
        # Clear from session after displaying once
        del request.session['emergency_token']
        del request.session['token_username']
    
    return render(request, 'core/emergency_access.html', context)

@login_required
@permission_required('core.manage_emergency_access', raise_exception=True)
@require_POST
def activate_emergency(request):
    """Activate emergency mode"""
    reason = request.POST.get('reason')
    if not reason:
        messages.error(request, "A reason must be provided to activate emergency mode.")
        return redirect('emergency_access_dashboard')
    
    EmergencyAccessProtocol.activate_emergency_mode(request.user, reason)
    messages.warning(request, "Emergency mode has been activated. Security protocols are in a reduced state.")
    return redirect('emergency_access_dashboard')

@login_required
@permission_required('core.manage_emergency_access', raise_exception=True)
@require_POST
def deactivate_emergency(request):
    """Deactivate emergency mode"""
    EmergencyAccessProtocol.deactivate_emergency_mode(request.user)
    messages.success(request, "Emergency mode has been deactivated. All security protocols restored.")
    return redirect('emergency_access_dashboard')

@login_required
@permission_required('core.manage_emergency_access', raise_exception=True)
@require_POST
def generate_emergency_token(request):
    """Generate emergency token for a user"""
    username = request.POST.get('username')
    reason = request.POST.get('reason')
    
    if not username or not reason:
        messages.error(request, "Both username and reason are required.")
        return redirect('emergency_access_dashboard')
    
    try:
        user = User.objects.get(username=username)
        token = EmergencyAccessProtocol.generate_emergency_token(user, request.user)
        
        # Store in session temporarily so it can be displayed once
        request.session['emergency_token'] = token
        request.session['token_username'] = user.username
        
        messages.info(request, f"Emergency token generated for {user.username}")
    except User.DoesNotExist:
        messages.error(request, f"User '{username}' not found.")
    except Exception as e:
        logger.error(f"Error generating emergency token: {str(e)}")
        messages.error(request, f"Error generating token: {str(e)}")
    
    return redirect('emergency_access_dashboard')

def emergency_login_page(request):
    """Emergency login page"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    return render(request, 'core/emergency_login.html')

@require_POST
def emergency_login(request):
    """Process emergency token login"""
    username = request.POST.get('username')
    token = request.POST.get('emergency_token')
    
    if not username or not token:
        return render(request, 'core/emergency_login.html', {
            'error_message': 'Both username and token are required.'
        })
    
    try:
        user = User.objects.get(username=username)
        valid = EmergencyAccessProtocol.verify_emergency_token(user, token)
        
        if valid:
            # Log the user in
            login(request, user)
            messages.warning(request, "You've been logged in using emergency access. " +
                            "This has been recorded for security purposes.")
            return redirect('dashboard')
        else:
            return render(request, 'core/emergency_login.html', {
                'error_message': 'Invalid or expired emergency token.'
            })
    except User.DoesNotExist:
        return render(request, 'core/emergency_login.html', {
            'error_message': 'User not found.'
        })
    except Exception as e:
        logger.error(f"Emergency login error: {str(e)}")
        return render(request, 'core/emergency_login.html', {
            'error_message': 'An error occurred during emergency login.'
        })
