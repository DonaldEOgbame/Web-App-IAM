import logging
import os
import hashlib
import base64
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .models import AuditLog, User
from django.core.mail import send_mail
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)

class EmergencyAccessProtocol:
    """
    Emergency access protocol for critical situations.
    Allows system administrators to enable emergency access mode
    which bypasses certain security requirements.
    """
    
    @staticmethod
    def activate_emergency_mode(activated_by, reason):
        """
        Activate emergency access mode
        
        Args:
            activated_by: User who activated emergency mode
            reason: Reason for activation
        """
        from django.core.cache import cache
        
        # Set the emergency mode flag
        settings.EMERGENCY_ACCESS_MODE = True
        
        # Cache the emergency mode status for 24 hours
        cache.set('emergency_access_mode', True, 86400)  # 24 hours
        
        # Create audit log entry
        AuditLog.objects.create(
            user=activated_by,
            action="EMERGENCY_MODE_ACTIVATED",
            details=f"Emergency access mode activated. Reason: {reason}",
            ip_address="System"
        )
        
        # Log the event
        logger.critical(f"EMERGENCY ACCESS MODE ACTIVATED by {activated_by.username}. Reason: {reason}")
        
        # Notify all administrators
        EmergencyAccessProtocol._notify_administrators(
            f"Emergency access mode activated by {activated_by.username}",
            f"Emergency access mode has been activated.\n\nReason: {reason}\n\nActivated by: {activated_by.username}\nTime: {timezone.now()}\n\nAll security protocols are now in reduced state. This should only be used in critical situations."
        )
        
        return True
    
    @staticmethod
    def deactivate_emergency_mode(deactivated_by):
        """
        Deactivate emergency access mode
        
        Args:
            deactivated_by: User who deactivated emergency mode
        """
        from django.core.cache import cache
        
        # Clear the emergency mode flag
        settings.EMERGENCY_ACCESS_MODE = False
        
        # Remove from cache
        cache.delete('emergency_access_mode')
        
        # Create audit log entry
        AuditLog.objects.create(
            user=deactivated_by,
            action="EMERGENCY_MODE_DEACTIVATED",
            details="Emergency access mode deactivated",
            ip_address="System"
        )
        
        # Log the event
        logger.critical(f"EMERGENCY ACCESS MODE DEACTIVATED by {deactivated_by.username}")
        
        # Notify all administrators
        EmergencyAccessProtocol._notify_administrators(
            f"Emergency access mode deactivated by {deactivated_by.username}",
            f"Emergency access mode has been deactivated.\n\nDeactivated by: {deactivated_by.username}\nTime: {timezone.now()}\n\nAll security protocols have been restored."
        )
        
        return True
    
    @staticmethod
    def check_emergency_mode():
        """Check if emergency mode is active"""
        from django.core.cache import cache
        
        # Check cache first for performance
        cache_status = cache.get('emergency_access_mode')
        if cache_status is not None:
            return cache_status
            
        return settings.EMERGENCY_ACCESS_MODE
    
    @staticmethod
    def generate_emergency_token(user, admin_user=None):
        """
        Generate a one-time emergency access token for a user
        
        Args:
            user: User to generate token for
            admin_user: Admin user generating the token (optional)
        
        Returns:
            str: Emergency access token
        """
        # Generate a secure random token
        token_bytes = os.urandom(32)
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8')[:20]  # Take first 20 chars for usability
        
        # Hash for storage
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store the token hash with the user
        user.emergency_token_hash = token_hash
        user.emergency_token_expiry = timezone.now() + timedelta(hours=4)  # Valid for 4 hours
        user.save(update_fields=['emergency_token_hash', 'emergency_token_expiry'])
        
        # Log the action
        admin_details = f" by {admin_user.username}" if admin_user else ""
        AuditLog.objects.create(
            user=admin_user or user,
            affected_user=user,
            action="EMERGENCY_TOKEN_GENERATED",
            details=f"Emergency access token generated for {user.username}{admin_details}",
            ip_address="System"
        )
        
        logger.warning(f"Emergency access token generated for {user.username}{admin_details}")
        
        return token
    
    @staticmethod
    def verify_emergency_token(user, token):
        """
        Verify an emergency access token for a user
        
        Args:
            user: User attempting to use the token
            token: The emergency token to verify
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Check if the user has an emergency token
        if not user.emergency_token_hash or not user.emergency_token_expiry:
            logger.warning(f"Emergency token verification failed for {user.username}: No token exists")
            return False
        
        # Check if the token has expired
        if user.emergency_token_expiry < timezone.now():
            logger.warning(f"Emergency token verification failed for {user.username}: Token expired")
            return False
        
        # Hash and compare the token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash != user.emergency_token_hash:
            logger.warning(f"Emergency token verification failed for {user.username}: Invalid token")
            return False
        
        # Clear the token after use
        user.emergency_token_hash = None
        user.emergency_token_expiry = None
        user.save(update_fields=['emergency_token_hash', 'emergency_token_expiry'])
        
        # Log successful verification
        AuditLog.objects.create(
            user=user,
            action="EMERGENCY_ACCESS_GRANTED",
            details="Emergency access token successfully used",
            ip_address="System"
        )
        
        logger.warning(f"Emergency access token successfully used by {user.username}")
        
        return True
    
    @staticmethod
    def _notify_administrators(subject, message):
        """Send notification to all administrators"""
        admins = User.objects.filter(role='ADMIN', is_active=True)
        admin_emails = [admin.email for admin in admins if admin.email]
        
        if admin_emails:
            try:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    admin_emails,
                    fail_silently=True
                )
            except Exception as e:
                logger.error(f"Failed to send emergency notification: {str(e)}")
