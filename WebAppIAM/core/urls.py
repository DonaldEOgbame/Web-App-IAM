from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .health import health_check
from . import emergency_views

app_name = 'core'

urlpatterns = [
    # Health Check
    path('health/', health_check, name='health_check'),

    # Authentication URLs
    path('register/', views.register, name='register'),
    path('register/biometrics/', views.register_biometrics, name='register_biometrics'),
    path('register/webauthn/options/', views.webauthn_registration_options, name='webauthn_registration_options'),
    path('register/webauthn/verify/', views.webauthn_registration_verify, name='webauthn_registration_verify'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('verify/biometrics/', views.verify_biometrics, name='verify_biometrics'),
    path('webauthn/auth/options/', views.webauthn_authentication_options, name='webauthn_authentication_options'),
    path('webauthn/auth/verify/', views.webauthn_authentication_verify, name='webauthn_authentication_verify'),

    # Emergency Access URLs
    path('emergency/login/', emergency_views.emergency_login_page, name='emergency_login_page'),
    path('emergency/access/', emergency_views.emergency_login, name='emergency_login'),
    path('admin/emergency/', emergency_views.emergency_access_dashboard, name='emergency_access_dashboard'),
    path('admin/emergency/activate/', emergency_views.activate_emergency, name='activate_emergency'),
    path('admin/emergency/deactivate/', emergency_views.deactivate_emergency, name='deactivate_emergency'),
    path('admin/emergency/generate-token/', emergency_views.generate_emergency_token, name='generate_emergency_token'),

    # Password Reset URLs
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset/confirm/<int:user_id>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),

    # Email verification
    path('verify_email/<int:user_id>/<str:token>/', views.verify_email, name='verify_email'),
    path('verify_email_update/<str:token>/', views.verify_email_update, name='verify_email_update'),

    # Dashboard URLs
    path('staff/dashboard/', views.staff_dashboard, name='staff_dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),

    # Admin Management URLs
    path('admin/users/activate/<int:user_id>/', views.activate_user, name='activate_user'),
    path('admin/users/lock/<int:user_id>/', views.lock_user, name='lock_user'),
    path('admin/users/unlock/<int:user_id>/', views.unlock_user, name='unlock_user'),
    path('admin/users/force-reenroll/<int:user_id>/', views.force_reenroll, name='force_reenroll'),

    # System Administration
    path('admin/system/status/', views.system_status, name='system_status'),
    path('admin/system/toggle-feature/', views.toggle_feature, name='toggle_feature'),

    # Profile Management
    path('complete_profile/', views.complete_profile, name='complete_profile'),
    path('profile/settings/', views.profile_settings, name='profile_settings'),

    # Document Management
    path('documents/', views.document_list, name='document_list'),
    path('documents/upload/', views.document_upload, name='document_upload'),
    path('documents/download/<int:doc_id>/', views.document_download, name='document_download'),
    path('documents/versions/<int:doc_id>/', views.document_versions, name='document_versions'),
    path('documents/restore/<int:doc_id>/', views.restore_document_version, name='restore_document_version'),
    path('documents/purge/<int:doc_id>/', views.purge_document, name='purge_document'),
    path('documents/validate_checksum/<int:doc_id>/', views.validate_checksum, name='validate_checksum'),

    # Audit Logs
    path('admin/audit_logs/', views.audit_logs, name='audit_logs'),
    path('admin/audit_logs/export/', views.export_audit_logs, name='export_audit_logs'),

    # Device Management
    path('devices/', views.manage_devices, name='manage_devices'),
    path('devices/trust/<int:device_id>/', views.trust_device, name='trust_device'),
    path('devices/remove/<int:device_id>/', views.remove_device, name='remove_device'),

    # Notification System
    path('notifications/', views.notifications_view, name='notifications'),
    path('notifications/dismiss/<int:notification_id>/', views.dismiss_device_notification, name='dismiss_device_notification'),
    path('notifications/mark_read/<int:notification_id>/', views.mark_notification_read, name='mark_notification_read'),
]