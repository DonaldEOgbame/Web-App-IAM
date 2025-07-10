from django.contrib import admin
from .models import User, UserBehaviorProfile, WebAuthnCredential, UserSession, RiskPolicy, AuditLog
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'role', 'FACE_ENROLLED', 'FINGERPRINT_ENROLLED', 'is_active', 'is_staff')
    actions = ['lock_user', 'unlock_user', 'force_reenroll']

    def lock_user(self, request, queryset):
        queryset.update(is_active=False)
    lock_user.short_description = 'Lock selected users'

    def unlock_user(self, request, queryset):
        queryset.update(is_active=True)
    unlock_user.short_description = 'Unlock selected users'

    def force_reenroll(self, request, queryset):
        queryset.update(FACE_ENROLLED=False, FINGERPRINT_ENROLLED=False)
    force_reenroll.short_description = 'Force biometric re-enrollment'

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
