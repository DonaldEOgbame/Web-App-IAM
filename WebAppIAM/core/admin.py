from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.contrib import messages
from .models import (
    User, UserProfile, UserBehaviorProfile, WebAuthnCredential, 
    UserSession, RiskPolicy, AuditLog, Document, DocumentAccessLog,
    Notification, DeviceFingerprint
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin options for the custom User model with enhanced activation controls and risk override."""
    
    list_display = (
        "username",
        "email",
        "role",
        "has_biometrics",
        "is_active",
        "is_staff",
        "date_joined",
        "activation_actions",
        "risk_override_status"
    )
    
    list_filter = ("role", "is_active", "is_staff", "date_joined", "admin_high_risk_override")
    list_editable = ("is_active",)  # Allows quick activation/deactivation
    
    # Add role field to both edit and add forms
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Additional Info", {"fields": ("role", "azure_face_id", "last_activity", "admin_high_risk_override")}),
        ("Security Settings", {"fields": ("failed_login_attempts", "last_failed_login", "force_reenroll")}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ("Additional Info", {"fields": ("role",)}),
    )
    
    readonly_fields = ("failed_login_attempts", "last_failed_login")
    actions = ["activate_users", "deactivate_users", "enable_risk_override", "disable_risk_override", "force_reenroll_users"]
    
    def has_biometrics(self, obj):
        return obj.has_biometrics
    has_biometrics.short_description = 'Biometrics Enrolled'
    has_biometrics.boolean = True
    
    def activation_actions(self, obj):
        if obj.is_active:
            return format_html(
                '<a class="button" href="{}">Deactivate</a>',
                reverse('admin:user_deactivate', args=[obj.pk])
            )
        else:
            return format_html(
                '<a class="button" href="{}">Activate</a>',
                reverse('admin:user_activate', args=[obj.pk])
            )
    activation_actions.short_description = 'Actions'
    
    def risk_override_status(self, obj):
        if obj.admin_high_risk_override:
            return format_html(
                '<span style="color: green; font-weight: bold;">Override Active</span>'
                '<a class="button" href="{}" '
                'style="margin-left:8px; background-color: #ff6b6b; border-color: #ff6b6b;">Disable</a>',
                reverse('admin:user_disable_risk_override', args=[obj.pk])
            )
        else:
            return format_html(
                '<a class="button" href="{}">Allow Risky Login</a>',
                reverse('admin:user_enable_risk_override', args=[obj.pk])
            )
    risk_override_status.short_description = 'Risk Override'
    
    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} users were successfully activated.")
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} users were successfully deactivated.")
    deactivate_users.short_description = "Deactivate selected users"
    
    def enable_risk_override(self, request, queryset):
        updated = queryset.update(admin_high_risk_override=True)
        self.message_user(
            request, 
            f"Risk override enabled for {updated} users. They will be allowed to bypass risk restrictions on their next login attempt.",
            messages.WARNING
        )
    enable_risk_override.short_description = "Allow risky login for selected users"
    
    def disable_risk_override(self, request, queryset):
        updated = queryset.update(admin_high_risk_override=False)
        self.message_user(
            request, 
            f"Risk override disabled for {updated} users.",
            messages.SUCCESS
        )
    disable_risk_override.short_description = "Disable risk override for selected users"
    
    def force_reenroll_users(self, request, queryset):
        for user in queryset:
            user.require_reenrollment()
        self.message_user(
            request, 
            f"Biometric re-enrollment required for {queryset.count()} users.",
            messages.WARNING
        )
    force_reenroll_users.short_description = "Force biometric re-enrollment"
    
    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('<id>/activate/',
                 self.admin_site.admin_view(self.activate_user),
                 name='user_activate'),
            path('<id>/deactivate/',
                 self.admin_site.admin_view(self.deactivate_user),
                 name='user_deactivate'),
            path('<id>/enable-risk-override/',
                 self.admin_site.admin_view(self.enable_risk_override_single),
                 name='user_enable_risk_override'),
            path('<id>/disable-risk-override/',
                 self.admin_site.admin_view(self.disable_risk_override_single),
                 name='user_disable_risk_override'),
        ]
        return custom_urls + urls
    
    def activate_user(self, request, id):
        user = User.objects.get(id=id)
        user.is_active = True
        user.save()
        self.message_user(request, f"User {user.username} was successfully activated.")
        return HttpResponseRedirect(reverse('admin:core_user_changelist'))
    
    def deactivate_user(self, request, id):
        user = User.objects.get(id=id)
        user.is_active = False
        user.save()
        self.message_user(request, f"User {user.username} was successfully deactivated.")
        return HttpResponseRedirect(reverse('admin:core_user_changelist'))
    
    def enable_risk_override_single(self, request, id):
        user = User.objects.get(id=id)
        user.admin_high_risk_override = True
        user.save()
        self.message_user(
            request, 
            f"Risk override enabled for {user.username}. They will be allowed to bypass risk restrictions on their next login attempt.",
            messages.WARNING
        )
        return HttpResponseRedirect(reverse('admin:core_user_changelist'))
    
    def disable_risk_override_single(self, request, id):
        user = User.objects.get(id=id)
        user.admin_high_risk_override = False
        user.save()
        self.message_user(
            request, 
            f"Risk override disabled for {user.username}.",
            messages.SUCCESS
        )
        return HttpResponseRedirect(reverse('admin:core_user_changelist'))


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'login_time', 'ip_address', 'risk_level', 'access_granted', 'session_actions')
    list_filter = ('risk_level', 'access_granted', 'login_time')
    search_fields = ('user__username', 'ip_address')
    
    def session_actions(self, obj):
        actions = []
        if not obj.access_granted and obj.risk_level in ['HIGH', 'CRITICAL']:
            actions.append(
                format_html(
                    '<a class="button" href="{}">Allow Access</a>',
                    reverse('admin:session_allow_access', args=[obj.pk])
                )
            )
        
        if obj.user.admin_high_risk_override:
            actions.append(
                format_html(
                    '<a class="button" href="{}" style="margin-left:8px; background-color: #ff6b6b; border-color: #ff6b6b;">Disable Override</a>',
                    reverse('admin:user_disable_risk_override', args=[obj.user.pk])
                )
            )
        
        return format_html(' '.join(actions)) if actions else "-"
    session_actions.short_description = 'Actions'
    
    def get_urls(self):
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('<id>/allow-access/',
                 self.admin_site.admin_view(self.allow_access),
                 name='session_allow_access'),
        ]
        return custom_urls + urls
    
    def allow_access(self, request, id):
        session = UserSession.objects.get(id=id)
        session.access_granted = True
        session.flagged_reason = 'Admin override for denied session'
        session.save()
        
        user = session.user
        user.admin_high_risk_override = True
        user.save()
        
        self.message_user(
            request, 
            f"Access granted for session and risk override enabled for {user.username}.",
            messages.WARNING
        )
        return HttpResponseRedirect(reverse('admin:core_usersession_changelist'))


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'full_name', 'department', 'position', 'access_level')
    list_filter = ('department', 'access_level')
    search_fields = ('user__username', 'full_name', 'department')


@admin.register(UserBehaviorProfile)
class UserBehaviorProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'typical_login_time', 'typical_device', 'typical_location')
    search_fields = ('user__username',)


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ('user', 'credential_id', 'created_at', 'last_used_at')
    search_fields = ('user__username',)


@admin.register(RiskPolicy)
class RiskPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'face_match_threshold', 'behavior_anomaly_threshold', 
                   'fingerprint_required', 'high_risk_action', 'is_active')
    list_filter = ('is_active',)
    list_editable = ('is_active',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp', 'ip_address')
    search_fields = ('user__username', 'action', 'ip_address', 'details')
    list_filter = ('action', 'timestamp')
    readonly_fields = ('timestamp',)


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('title', 'access_level', 'required_access_level', 
                   'department', 'uploaded_by', 'created_at')
    list_filter = ('access_level', 'required_access_level', 'department')
    search_fields = ('title', 'description', 'department')


@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'document', 'timestamp', 'access_type', 'was_successful', 'ip_address')
    list_filter = ('was_successful', 'access_type', 'timestamp')
    search_fields = ('user__username', 'document__title', 'ip_address')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message_preview', 'created_at', 'read', 'notification_type')
    list_filter = ('read', 'notification_type', 'created_at')
    search_fields = ('user__username', 'message')
    list_editable = ('read',)
    
    def message_preview(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message
    message_preview.short_description = 'Message'


@admin.register(DeviceFingerprint)
class DeviceFingerprintAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_name', 'browser', 'operating_system', 
                   'is_trusted', 'first_seen', 'last_seen')
    list_filter = ('is_trusted', 'device_type', 'browser', 'operating_system')
    search_fields = ('user__username', 'device_name', 'browser')
    list_editable = ('is_trusted',)
