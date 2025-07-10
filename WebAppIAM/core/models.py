
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.conf import settings

class UserNotification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    type = models.CharField(max_length=32, default='info')  # info, warning, risk, expiry, etc.
    link = models.CharField(max_length=256, blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}: {self.message[:40]}..."


class User(AbstractUser):
    FACE_ENROLLED = models.BooleanField(default=False)
    FINGERPRINT_ENROLLED = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=[('USER', 'User'), ('ADMIN', 'Admin')], default='USER')
    azure_face_id = models.CharField(max_length=100, blank=True, null=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    email_verified = models.BooleanField(default=False)

class UserPreference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='preference')
    show_risk_alerts = models.BooleanField(default=True)
    show_face_match = models.BooleanField(default=False)
    auto_logout = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Preferences for {self.user.username}"

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

# --- Secure Document Vault Models ---


class Document(models.Model):
    ACCESS_LEVEL_CHOICES = [
        ('ADMIN', 'Admin Only'),
        ('USER', 'All Users'),
        ('DEPT', 'Department Specific'),
    ]
    CATEGORY_CHOICES = [
        ('GENERAL', 'General'),
        ('HR', 'HR'),
        ('FINANCE', 'Finance'),
        ('IT', 'IT'),
        ('LEGAL', 'Legal'),
        # Add more as needed
    ]
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/')
    description = models.TextField(blank=True)
    access_level = models.CharField(max_length=10, choices=ACCESS_LEVEL_CHOICES, default='USER')
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='GENERAL')
    department = models.CharField(max_length=100, blank=True, null=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1, help_text="Document version number.")
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL, related_name='versions', help_text="Previous version of this document, if any.")
    deleted = models.BooleanField(default=False, help_text="Soft delete flag for archival.")



    def __str__(self):
        return f"{self.title} (v{self.version})" if self.version > 1 else self.title

    def is_expired(self):
        from django.utils import timezone
        return self.expiry_date and self.expiry_date < timezone.now()

    def get_status_badge(self):
        from django.utils import timezone
        if self.deleted:
            return ("Archived", "secondary")
        if self.is_expired():
            return ("Expired", "danger")
        if self.expiry_date:
            delta = self.expiry_date - timezone.now()
            if delta.days <= 7 and delta.days >= 0:
                return ("Expiring Soon", "warning")
        return ("Active", "success")

    def get_watermarked_file(self):
        """
        Returns a file-like object or path to a watermarked PDF if the document is a PDF.
        For non-PDFs, returns the original file.
        """
        import os
        from django.core.files.base import ContentFile
        from django.core.files.storage import default_storage
        from PyPDF2 import PdfReader, PdfWriter
        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter

        if not self.file.name.lower().endswith('.pdf'):
            return self.file

        # Read the original PDF
        original_pdf = self.file.open('rb')
        reader = PdfReader(original_pdf)
        writer = PdfWriter()

        # Create watermark PDF in memory
        watermark_stream = BytesIO()
        c = canvas.Canvas(watermark_stream, pagesize=letter)
        c.setFont("Helvetica", 36)
        c.setFillColorRGB(0.6, 0.6, 0.6, alpha=0.3)
        c.saveState()
        c.translate(300, 400)
        c.rotate(45)
        c.drawCentredString(0, 0, "CONFIDENTIAL")
        c.restoreState()
        c.save()
        watermark_stream.seek(0)

        watermark_reader = PdfReader(watermark_stream)
        watermark_page = watermark_reader.pages[0]

        # Merge watermark with each page
        for page in reader.pages:
            page.merge_page(watermark_page)
            writer.add_page(page)

        output_stream = BytesIO()
        writer.write(output_stream)
        output_stream.seek(0)

        # Save to a temporary file in storage
        watermarked_name = os.path.splitext(self.file.name)[0] + '_watermarked.pdf'
        content = ContentFile(output_stream.read())
        saved_path = default_storage.save(f'documents/watermarked/{watermarked_name}', content)
        return saved_path

class DocumentAccessLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='access_logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    face_score = models.FloatField(null=True, blank=True)
    fingerprint_status = models.BooleanField(default=False)
    risk_score = models.FloatField(null=True, blank=True)
    was_blocked = models.BooleanField(default=False)
    session = models.ForeignKey('UserSession', on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.user} accessed {self.document} at {self.timestamp}"