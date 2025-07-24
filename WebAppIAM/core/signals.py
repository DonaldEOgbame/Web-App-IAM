from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import AuditLog, User, Document, UserSession
from django.conf import settings
import socket

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    """Log user login activity"""
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    AuditLog.objects.create(
        user=user,
        action='USER_LOGIN',
        details=f'User login from {ip_address} using {user_agent}',
        ip_address=ip_address
    )
    
    # Update user's last activity
    user.last_activity = timezone.now()
    user.save(update_fields=['last_activity'])

@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    """Log user logout activity"""
    if user:
        ip_address = get_client_ip(request)
        
        AuditLog.objects.create(
            user=user,
            action='USER_LOGOUT',
            details=f'User logout from {ip_address}',
            ip_address=ip_address
        )

@receiver(user_login_failed)
def user_login_failed_callback(sender, credentials, request, **kwargs):
    """Log failed login attempts"""
    ip_address = get_client_ip(request) if request else 'Unknown'
    username = credentials.get('username', 'unknown')
    
    AuditLog.objects.create(
        user=None,
        action='LOGIN_FAILED',
        details=f'Failed login attempt for username: {username}',
        ip_address=ip_address
    )

@receiver(post_save, sender=Document)
def document_activity_callback(sender, instance, created, **kwargs):
    """Log document creation and updates"""
    if created:
        action = 'DOCUMENT_CREATED'
        details = f'Document created: {instance.title} (v{instance.version})'
    else:
        action = 'DOCUMENT_UPDATED'
        details = f'Document updated: {instance.title} (v{instance.version})'
    
    AuditLog.objects.create(
        user=instance.uploaded_by,
        action=action,
        details=details,
        ip_address='System'
    )

@receiver(post_delete, sender=Document)
def document_deleted_callback(sender, instance, **kwargs):
    """Log document deletion"""
    AuditLog.objects.create(
        user=None,  # We might not know who deleted it
        action='DOCUMENT_DELETED',
        details=f'Document deleted: {instance.title} (v{instance.version})',
        ip_address='System'
    )
