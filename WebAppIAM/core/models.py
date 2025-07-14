from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.conf import settings
from django.utils import timezone

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('RISK', 'Security Risk'),
        ('EXPIRY', 'Document Expiry'),
        ('APPROVAL', 'Approval Required'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES, default='INFO')
    link = models.CharField(max_length=256, blank=True, null=True)
    action_required = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'read']),
        ]

    def __str__(self):
        return f"{self.user.username}: {self.message[:40]}..."

class User(AbstractUser):
    ROLE_CHOICES = [
        ('STUDENT', 'Student'),
        ('ADMIN', 'Administrator'),
    ]
    
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='STUDENT')
    azure_face_id = models.CharField(max_length=100, blank=True, null=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=255, blank=True, null=True)
    email_verification_expiration = models.DateTimeField(blank=True, null=True)
    face_data = models.BinaryField(null=True, blank=True)
    force_reenroll = models.BooleanField(default=False)  # Admin can force re-enrollment
    two_factor_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        permissions = [
            ("can_force_reenroll", "Can force biometric re-enrollment"),
            ("can_lock_account", "Can lock/unlock user accounts"),
            ("bypass_biometrics", "Can bypass biometric authentication"),
        ]

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

    @property
    def has_biometrics(self):
        """Check if user has enrolled either face data or WebAuthn credentials"""
        return bool(self.face_data) or self.webauthn_credentials.exists()

    @property
    def is_high_risk(self):
        """Check if user has any high-risk sessions in last 24 hours"""
        return UserSession.objects.filter(
            user=self,
            risk_level='HIGH',
            login_time__gte=timezone.now() - timezone.timedelta(hours=24)
        ).exists()

    def require_reenrollment(self):
        """Force user to re-enroll their biometrics"""
        self.force_reenroll = True
        self.face_data = None
        self.webauthn_credentials.all().delete()
        self.save()

class UserProfile(models.Model):
    DEPT_CHOICES = [
        ('HR', 'Human Resources'),
        ('FINANCE', 'Finance'),
        ('IT', 'Information Technology'),
        ('SALES', 'Sales'),
        ('MARKETING', 'Marketing'),
        ('OPERATIONS', 'Operations'),
        ('LEGAL', 'Legal'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    full_name = models.CharField(max_length=255)
    department = models.CharField(max_length=20, choices=DEPT_CHOICES)
    position = models.CharField(max_length=100)
    phone = models.CharField(max_length=20, blank=True, null=True)
    profile_completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Preferences
    show_risk_alerts = models.BooleanField(default=True)
    show_face_match = models.BooleanField(default=False)
    auto_logout = models.BooleanField(default=False)
    receive_email_alerts = models.BooleanField(default=True)
    
    def __str__(self):
        return f"Profile for {self.user.username}"

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webauthn_credentials')
    credential_id = models.TextField(unique=True)
    public_key = models.TextField()
    sign_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    device_name = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"WebAuthn credential for {self.user.username}"

class UserSession(models.Model):
    RISK_LEVELS = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Risk'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=255, blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    face_match_score = models.FloatField(
        null=True, 
        blank=True, 
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    fingerprint_verified = models.BooleanField(default=False)
    behavior_anomaly_score = models.FloatField(
        null=True, 
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    risk_score = models.FloatField(
        null=True, 
        blank=True, 
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='LOW')
    access_granted = models.BooleanField(default=False)
    flagged_reason = models.TextField(blank=True, null=True)
    forced_logout = models.BooleanField(default=False)
    location = models.CharField(max_length=100, blank=True, null=True)
    is_mobile = models.BooleanField(default=False)

    class Meta:
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', 'risk_level']),
            models.Index(fields=['login_time']),
        ]

    def __str__(self):
        return f"Session for {self.user.username} at {self.login_time}"

    @property
    def duration(self):
        if self.logout_time:
            return self.logout_time - self.login_time
        return timezone.now() - self.login_time

class RiskPolicy(models.Model):
    ACTIONS = [
        ('ALLOW', 'Allow access'),
        ('CHALLENGE', 'Require additional verification'),
        ('DENY', 'Deny access'),
        ('NOTIFY', 'Allow but notify admin'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Thresholds
    face_match_threshold = models.FloatField(
        default=0.75,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    behavior_anomaly_threshold = models.FloatField(
        default=0.6,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)]
    )
    fingerprint_required = models.BooleanField(default=True)
    
    # Risk actions
    low_risk_action = models.CharField(max_length=20, choices=ACTIONS, default='ALLOW')
    medium_risk_action = models.CharField(max_length=20, choices=ACTIONS, default='CHALLENGE')
    high_risk_action = models.CharField(max_length=20, choices=ACTIONS, default='DENY')
    critical_risk_action = models.CharField(max_length=20, choices=ACTIONS, default='DENY')
    
    # Special rules
    require_reauth_for_documents = models.BooleanField(default=True)
    lock_after_failed_attempts = models.PositiveIntegerField(default=5)
    session_timeout = models.PositiveIntegerField(
        default=30, 
        help_text="Inactivity timeout in minutes"
    )

    def __str__(self):
        return f"{self.name} {'(Active)' if self.is_active else ''}"

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('USER_REGISTER', 'User Registration'),
        ('USER_ACTIVATE', 'User Activation'),
        ('LOGIN_ATTEMPT', 'Login Attempt'),
        ('LOGIN_SUCCESS', 'Successful Login'),
        ('LOGIN_FAIL', 'Failed Login'),
        ('FACE_ENROLL', 'Face Enrollment'),
        ('FINGERPRINT_ENROLL', 'Fingerprint Enrollment'),
        ('RISK_EVAL', 'Risk Evaluation'),
        ('ACCESS_GRANTED', 'Access Granted'),
        ('ACCESS_DENIED', 'Access Denied'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('DOC_UPLOAD', 'Document Upload'),
        ('DOC_DOWNLOAD', 'Document Download'),
        ('DOC_DELETE', 'Document Deletion'),
        ('DOC_RESTORE', 'Document Restore'),
        ('POLICY_UPDATE', 'Policy Update'),
        ('ACCOUNT_LOCK', 'Account Locked'),
        ('ACCOUNT_UNLOCK', 'Account Unlocked'),
        ('FORCE_REENROLL', 'Forced Re-enrollment'),
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    details = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)
    affected_user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='affected_audit_logs'
    )

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action', 'timestamp']),
        ]

    def __str__(self):
        user = self.user.username if self.user else 'System'
        return f"{self.get_action_display()} by {user} at {self.timestamp}"

class Document(models.Model):
    ACCESS_LEVEL_CHOICES = [
        ('PRIVATE', 'Private (Owner Only)'),
        ('DEPT', 'Department Access'),
        ('ORG', 'Organization Access'),
        ('PUBLIC', 'Public Access'),
    ]
    
    CATEGORY_CHOICES = [
        ('GENERAL', 'General'),
        ('CONFIDENTIAL', 'Confidential'),
        ('RESTRICTED', 'Restricted'),
        ('SENSITIVE', 'Sensitive'),
        ('PUBLIC', 'Public'),
    ]
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Security metadata
    access_level = models.CharField(max_length=15, choices=ACCESS_LEVEL_CHOICES, default='PRIVATE')
    category = models.CharField(max_length=15, choices=CATEGORY_CHOICES, default='GENERAL')
    department = models.CharField(max_length=100, blank=True, null=True)
    
    # File handling
    encrypted_file = models.BinaryField()  # Stores encrypted file content
    original_filename = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)
    file_size = models.PositiveIntegerField()
    encryption_key = models.BinaryField()  # Encrypted encryption key
    
    # Versioning
    version = models.PositiveIntegerField(default=1)
    parent = models.ForeignKey(
        'self', 
        null=True, 
        blank=True, 
        on_delete=models.SET_NULL, 
        related_name='versions'
    )
    
    # Lifecycle
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='uploaded_documents'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    deleted = models.BooleanField(default=False)
    deletion_reason = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['access_level', 'category']),
            models.Index(fields=['department']),
        ]
        permissions = [
            ("can_restore_document", "Can restore deleted documents"),
            ("can_view_audit_log", "Can view document access logs"),
        ]

    def __str__(self):
        return f"{self.title} (v{self.version})" if self.version > 1 else self.title

    def is_expired(self):
        return self.expiry_date and self.expiry_date < timezone.now()

    def get_status(self):
        if self.deleted:
            return "Archived"
        if self.is_expired():
            return "Expired"
        if self.expiry_date:
            delta = self.expiry_date - timezone.now()
            if delta.days <= 7:
                return "Expiring Soon"
        return "Active"

    def get_status_class(self):
        status = self.get_status()
        return {
            "Archived": "secondary",
            "Expired": "danger",
            "Expiring Soon": "warning",
            "Active": "success"
        }.get(status, "primary")

class DocumentAccessLog(models.Model):
    ACCESS_TYPES = [
        ('DOWNLOAD', 'Download'),
        ('PREVIEW', 'Preview'),
        ('SHARE', 'Share'),
        ('EDIT', 'Edit'),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='document_accesses'
    )
    document = models.ForeignKey(
        Document, 
        on_delete=models.CASCADE, 
        related_name='access_logs'
    )
    access_type = models.CharField(max_length=10, choices=ACCESS_TYPES, default='DOWNLOAD')
    timestamp = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)
    reason = models.TextField(blank=True, null=True)
    session = models.ForeignKey(
        UserSession, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='document_accesses'
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    device_info = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['document', 'was_successful']),
            models.Index(fields=['user', 'access_type']),
        ]

    def __str__(self):
        action = "accessed" if self.was_successful else "attempted to access"
        return f"{self.user} {action} {self.document} at {self.timestamp}"