"""
Django settings for WebAppIAM project.

Generated by 'django-admin startproject' using Django 5.0.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-i(ifrhq$^wcyi7_8sbj7l7#-n%p=kuw0abzo)t$jmjzr1a!=%z'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core.security_middleware.StrictTransportSecurityMiddleware',  # HSTS middleware
    'core.security_middleware.ContentSecurityPolicyMiddleware',  # CSP middleware
    'core.security_middleware.APICSRFProtectionMiddleware',  # API CSRF protection
    'core.middleware.SessionSecurityMiddleware',  # Session security middleware
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'WebAppIAM.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'WebAppIAM.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Use custom user model
AUTH_USER_MODEL = 'core.User'
LOGIN_URL = '/login/'


# Email settings
#
# Default to the console backend in development so that the application
# doesn't attempt to connect to the external SMTP server when running
# locally or in restricted environments.  The backend can be overridden
# via the ``EMAIL_BACKEND`` environment variable for production.
# ``EMAIL_HOST_USER`` and ``EMAIL_HOST_PASSWORD`` can also be supplied via
# environment variables.
EMAIL_BACKEND = os.environ.get(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend" if DEBUG else "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp-mail.outlook.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True") == "True"
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "webappIAM@outlook.com")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "thenewpasswordisgreat!@##")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER)
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", "10"))

# Face recognition configuration (DeepFace)
FACE_API_ENABLED = True
FACE_ENROLL_DIR = os.environ.get('FACE_ENROLL_DIR', os.path.join(BASE_DIR, 'faces'))
DEEPFACE_MODEL_NAME = os.environ.get('DEEPFACE_MODEL_NAME', 'ArcFace')
DEEPFACE_DISTANCE_METRIC = os.environ.get('DEEPFACE_DISTANCE_METRIC', 'cosine')
DEEPFACE_DETECTOR_BACKEND = os.environ.get('DEEPFACE_DETECTOR_BACKEND', 'retinaface')
DEEPFACE_THRESHOLD = float(os.environ.get('DEEPFACE_THRESHOLD', '0.40'))

# Video enrollment
ENROLL_VIDEO_ENABLED = True
ENROLL_VIDEO_SAMPLE_FPS = 3.0
ENROLL_VIDEO_MAX_FRAMES = 30
ENROLL_VIDEO_TOP_K = 5
ENROLL_FACE_MIN_SIDE = 180
ENROLL_SHARPNESS_MIN = 80.0

# Timeouts
REQUEST_TIMEOUT_HEALTH = 5
REQUEST_TIMEOUT_OPS = 15

# WebAuthn Configuration
# Defaults provide sensible values for local development but can be overridden
# with environment variables for production deployments.
WEBAUTHN_ENABLED = os.environ.get('WEBAUTHN_ENABLED', 'True') == 'True'
WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
WEBAUTHN_RP_NAME = os.environ.get('WEBAUTHN_RP_NAME', 'WebAppIAM')
WEBAUTHN_EXPECTED_ORIGIN = os.environ.get('WEBAUTHN_EXPECTED_ORIGIN', 'http://localhost:8001')

# Risk Engine Weights
RISK_FACE_WEIGHT = 0.4
RISK_FINGERPRINT_WEIGHT = 0.4
RISK_BEHAVIOR_WEIGHT = 0.2

# Feature Flags
# Face API toggled above; keep here for clarity
RISK_ENGINE_BYPASS = False  # Maintenance mode for risk engine
EMERGENCY_ACCESS_MODE = False  # Emergency access mode for critical situations

# Session Settings
SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
STRICT_SESSION_SECURITY = True  # Enable strict session security checking

# Account Security Settings
MAX_FAILED_LOGINS = 5  # Maximum failed login attempts before lockout
ACCOUNT_LOCKOUT_MINUTES = 30  # Lock account for 30 minutes after too many failed attempts

# CSRF Settings
CSRF_EXEMPT_PATHS = [
    '/core/webauthn/auth/',  # WebAuthn authentication endpoints
    '/core/health/'  # Health check endpoint
]

# Machine Learning models directory
# Allows override via environment variable for flexible deployments.
ML_MODELS_DIR = os.environ.get(
    "ML_MODELS_DIR",
    os.path.join(BASE_DIR, "ml_pipeline", "models", "production")
)
