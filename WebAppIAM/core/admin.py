from django.contrib import admin
from .models import User, UserBehaviorProfile, WebAuthnCredential, UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin options for the custom :class:`User` model."""

    list_display = (
        "username",
        "role",
        "has_biometrics",
        "is_active",
        "is_staff",
    )
    list_filter = ("role", "is_active", "is_staff")
    actions = ["lock_user", "unlock_user"]

    # Expose the role field when editing or creating a user
    fieldsets = BaseUserAdmin.fieldsets + ((None, {"fields": ("role",)}),)
    add_fieldsets = BaseUserAdmin.add_fieldsets + ((None, {"fields": ("role",)}),)

    def has_biometrics(self, obj):
        return obj.has_biometrics
    has_biometrics.short_description = 'Biometrics Enrolled'
    has_biometrics.boolean = True

    def lock_user(self, request, queryset):
        queryset.update(is_active=False)
    lock_user.short_description = 'Lock selected users'

    def unlock_user(self, request, queryset):
        queryset.update(is_active=True)
    unlock_user.short_description = 'Unlock selected users'


@admin.register(UserBehaviorProfile)
class UserBehaviorProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'typical_login_time', 'typical_device', 'typical_location')

@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ('user', 'credential_id', 'created_at', 'last_used_at')

@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'login_time', 'ip_address', 'risk_level', 'access_granted')
    list_filter = ('risk_level', 'access_granted')

@admin.register(RiskPolicy)
class RiskPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'face_match_threshold', 'behavior_anomaly_threshold', 'fingerprint_required', 'high_risk_action', 'is_active')
    list_filter = ('is_active',)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp', 'ip_address')
    search_fields = ('user__username', 'action', 'ip_address', 'details')
    list_filter = ('action',)

@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'access_level', 'department', 'uploaded_by', 'created_at')
    list_filter = ('access_level', 'department')
    search_fields = ('title', 'description', 'department')

@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'document', 'timestamp', 'access_type', 'was_successful', 'ip_address')
    list_filter = ('was_successful', 'access_type')
    search_fields = ('user__username', 'document__title', 'ip_address')
