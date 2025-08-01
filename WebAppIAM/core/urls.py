from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .health import health_check

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


    # Password Reset URLs
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset/confirm/<int:user_id>/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),

    # Email update verification
    path('verify_email_update/<str:token>/', views.verify_email_update, name='verify_email_update'),

    # Dashboard URLs
    path('staff/dashboard/', views.staff_dashboard, name='staff_dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin/users/', views.admin_users, name='admin_users'),

    # Admin Management URLs
    path('admin/users/activate/<int:user_id>/', views.activate_user, name='admin_activate_user'),
    path('admin/users/lock/<int:user_id>/', views.lock_user, name='admin_lock_user'),
    path('admin/users/unlock/<int:user_id>/', views.unlock_user, name='admin_unlock_user'),
    path('admin/users/access/<int:user_id>/<int:level>/', views.set_access_level, name='admin_set_access_level'),
    path('admin/sessions/allow/<int:session_id>/', views.allow_high_risk_session, name='allow_high_risk_session'),


    # Profile Management
    path('complete_profile/', views.complete_profile, name='complete_profile'),
    path('profile/settings/', views.profile_settings, name='profile_settings'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/change_password/', views.change_password, name='change_password'),

    # Document Management
    path('documents/', views.document_list, name='document_list'),
    path('documents/upload/', views.document_upload, name='document_upload'),
    path('documents/download/<int:doc_id>/', views.document_download, name='document_download'),
    path('documents/edit/<int:doc_id>/', views.document_edit, name='document_edit'),
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
    path('notifications/mark_all/', views.mark_all_notifications_read, name='mark_all_notifications_read'),

    # Access Denied
    path('access_denied/', views.access_denied, name='access_denied'),
]
