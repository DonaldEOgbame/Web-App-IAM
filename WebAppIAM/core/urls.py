from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'core'

urlpatterns = [
    # Authentication URLs
    path('register/', views.register, name='register'),
    path('register/biometrics/', views.register_biometrics, name='register_biometrics'),
    path('register/webauthn/options/', views.webauthn_registration_options, name='webauthn_registration_options'),
    path('register/webauthn/verify/', views.webauthn_registration_verify, name='webauthn_registration_verify'),
    path('reenroll_face/', views.reenroll_face, name='reenroll_face'),
    path('reregister_fingerprint/', views.reregister_fingerprint, name='reregister_fingerprint'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('verify/biometrics/', views.verify_biometrics, name='verify_biometrics'),
    path('webauthn/auth/options/', views.webauthn_authentication_options, name='webauthn_authentication_options'),
    path('webauthn/auth/verify/', views.webauthn_authentication_verify, name='webauthn_authentication_verify'),
    path('password_change/', views.password_change, name='password_change'),
    # Dashboard URLs
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    # Admin/Policy/Audit URLs
    path('admin/lock_user/<int:user_id>/', views.lock_user, name='lock_user'),
    path('admin/unlock_user/<int:user_id>/', views.unlock_user, name='unlock_user'),
    path('admin/force_reenroll/<int:user_id>/', views.force_reenroll, name='force_reenroll'),
    path('policy_editor/', views.policy_editor, name='policy_editor'),
    path('audit_logs/', views.audit_logs, name='audit_logs'),
    path('audit_logs/export/', views.export_audit_logs, name='export_audit_logs'),
    # Protected Resources
    path('secure_document/', views.secure_document, name='secure_document'),
    path('report_submission/', views.report_submission, name='report_submission'),
    path('personal_data/', views.personal_data, name='personal_data'),
    # Access Denied
    path('access_denied/', views.access_denied, name='access_denied'),
    # Password reset URLs (using Django's built-in views)
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    # Document Vault URLs
    path('documents/', views.document_list, name='document_list'),
    path('documents/upload/', views.document_upload, name='document_upload'),
    path('documents/download/<int:doc_id>/', views.document_download, name='document_download'),
    path('documents/reverify/<int:doc_id>/', views.document_reverify, name='document_reverify'),
    path('documents/access_logs/', views.document_access_logs, name='document_access_logs'),
    path('documents/restore/<int:doc_id>/', views.restore_document_version, name='restore_document_version'),
    # User Profile & Settings
    path('profile/', views.profile, name='profile'),
    path('settings/', views.settings, name='settings'),
    path('notifications/', views.notifications, name='notifications'),
]