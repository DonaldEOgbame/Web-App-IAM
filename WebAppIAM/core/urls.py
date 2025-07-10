from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
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
    
    # Dashboard URLs
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    
    # Password reset URLs (using Django's built-in views)
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
]