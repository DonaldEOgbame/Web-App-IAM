from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator

class User(AbstractUser):
    FACE_ENROLLED = models.BooleanField(default=False)
    FINGERPRINT_ENROLLED = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=[('USER', 'User'), ('ADMIN', 'Admin')], default='USER')
    azure_face_id = models.CharField(max_length=100, blank=True, null=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} ({self.role})"

class UserBehaviorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='behavior_profile')
    typical_login_time = models.TimeField(blank=True, null=True)
    typical_device = models.CharField(max_length=255, blank=True, null=True)
    typical_location = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Behavior profile for {self.user.username}"

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.TextField(unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"WebAuthn credential for {self.user.username}"

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=255, blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    face_match_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    fingerprint_verified = models.BooleanField(default=False)
    behavior_anomaly_score = models.FloatField(null=True, blank=True)
    risk_score = models.FloatField(null=True, blank=True, validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    risk_level = models.CharField(max_length=10, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High')
    ], default='LOW')
    access_granted = models.BooleanField(default=False)
    flagged_reason = models.TextField(blank=True, null=True)
    forced_logout = models.BooleanField(default=False)

    class Meta:
        ordering = ['-login_time']

    def __str__(self):
        return f"Session for {self.user.username} at {self.login_time}"

class RiskPolicy(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    face_match_threshold = models.FloatField(default=0.7, validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    behavior_anomaly_threshold = models.FloatField(default=0.5, validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    fingerprint_required = models.BooleanField(default=True)
    high_risk_action = models.CharField(max_length=20, choices=[
        ('ALLOW', 'Allow with monitoring'),
        ('CHALLENGE', 'Require additional authentication'),
        ('DENY', 'Deny access')
    ], default='CHALLENGE')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN_ATTEMPT', 'Login Attempt'),
        ('FACE_ENROLL', 'Face Enrollment'),
        ('FINGERPRINT_ENROLL', 'Fingerprint Enrollment'),
        ('RISK_EVAL', 'Risk Evaluation'),
        ('ACCESS_DENIED', 'Access Denied'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PROFILE_UPDATE', 'Profile Update'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    details = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.get_action_display()} by {self.user if self.user else 'System'} at {self.timestamp}"