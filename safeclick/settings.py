"""
Django settings for safeclick project - النسخة النهائية المتكاملة
"""

from pathlib import Path
import os
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables
load_dotenv()

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# ========== الأمان ==========
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-dev-key-change-in-production')
DEBUG = os.getenv('DJANGO_DEBUG', 'True') == 'True'

# DEVELOPMENT: Allow all hosts so physical devices on the LAN can connect.
# PRODUCTION: Set ALLOWED_HOSTS env var to your exact domain, e.g. 'safeclick.app'
if DEBUG:
    ALLOWED_HOSTS = ['*']
else:
    ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')

# ========== التطبيقات ==========
INSTALLED_APPS = [
    'jazzmin',  # Professional UI theme
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt',
    
    # Local apps
    'apps.accounts',
    'apps.scans',
    'apps.reports',
    'apps.core',
    'apps.feedback',
]

# ========== Middleware ==========
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'safeclick.middleware.AppAccessMiddleware',  # Phase 6: App-ID validation
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'safeclick.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'safeclick.wsgi.application'

# ========== قاعدة البيانات ==========
# الاعتماد حصراً على PostgreSQL 
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('safeclick_db', 'safeclick_db'),
        'USER': os.getenv('safeclick_user', 'safeclick_user'),
        'PASSWORD': os.getenv('salah', 'salah'),
        'HOST': os.getenv('localhost', 'localhost'),
        'PORT': os.getenv('5432', '5432'),
    }
}

# ========== التخزين المؤقت (Redis) ==========
# REDIS_URL = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1')

# Redis cache disabled temporarily as per user request
# try:
#     import django_redis
#     import redis
#     
#     # Try to ping the Redis server rapidly to see if it's actually alive
#     redis_test_client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=0.2)
#     redis_test_client.ping()
#     
#     CACHES = {
#         "default": {
#             "BACKEND": "django_redis.cache.RedisCache",
#             "LOCATION": REDIS_URL,
#             "OPTIONS": {
#                 "CLIENT_CLASS": "django_redis.client.DefaultClient",
#                 "IGNORE_EXCEPTIONS": True,
#                 "SOCKET_CONNECT_TIMEOUT": 2,
#                 "SOCKET_TIMEOUT": 2,
#             }
#         }
#     }
# except (ImportError, redis.exceptions.ConnectionError, redis.exceptions.TimeoutError, Exception) as e:
#     # Redis not installed OR server is down — use in-memory cache
#     print(f"ℹ️ [Cache] Redis unavailable ({str(e).split()[0]}). Falling back to LocMemCache.")
#     CACHES = {
#         "default": {
#             "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
#         }
#     }

# Use LocMemCache as default
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# ========== التحقق من كلمة المرور ==========
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 6,  # 6 أحرف للتطوير
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ========== اللغة والوقت ==========
LANGUAGE_CODE = 'ar'
TIME_ZONE = 'Asia/Riyadh'
USE_I18N = True
USE_TZ = True

# ========== الملفات الثابتة ==========
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []

# ========== ملفات الوسائط ==========
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# ========== المفتاح الأساسي ==========
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ========== نموذج المستخدم ==========
AUTH_USER_MODEL = 'accounts.User'

# ========== REST Framework ==========
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.core.pagination.StandardPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        # SECURITY: BrowsableAPIRenderer disabled — can expose tokens in HTML.
        # Re-enable ONLY during local development.
        # 'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.FormParser',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',  # Phase 7: per-endpoint limits
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '50/hour',
        'user': '100/hour',
        'scan': '10/minute',  # Phase 7: 10 scans/min per authenticated user
        'guest_scan': '3/day',  # Allow 3 scans per day for guests based on IP
    },
    'DATETIME_FORMAT': '%Y-%m-%d %H:%M:%S',
}

DEFAULT_CHARSET = 'utf-8'

# ========== JWT Settings ==========
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=30),      # 30 يوم بدلاً من ساعة
    'REFRESH_TOKEN_LIFETIME': timedelta(days=60),     # 60 يوم بدلاً من 7 أيام
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    
    # إضافات مهمة لتجربة المستخدم
    'UPDATE_LAST_LOGIN': True,           # تحديث آخر دخول مع كل طلب
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# ========== CORS Settings ==========
# SECURITY: CORS_ALLOW_ALL_ORIGINS=True is acceptable for local dev.
# In production, set CORS_ALLOW_ALL_ORIGINS=False and add exact origins to CORS_ALLOWED_ORIGINS.
CORS_ALLOW_ALL_ORIGINS = os.getenv('CORS_ALLOW_ALL_ORIGINS', 'True') == 'True'
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.8.110:3000",
    "http://192.168.8.110:8000",
]

# ========== CSRF Settings ==========
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.8.110:3000",
    "http://192.168.8.110:8000",
]

# ========== API Keys ==========
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
GOOGLE_WEB_CLIENT_ID = os.getenv('GOOGLE_WEB_CLIENT_ID', '')

# ========== Email Settings (Gmail SMTP) ==========
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'safeclicK17@gmail.com'
EMAIL_HOST_PASSWORD = 'jczy igib ztum ahku'
DEFAULT_FROM_EMAIL = 'SafeClick <safeclick17@gmail.com>'

# ========== Logging ==========
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'django.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'scans': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# ========== Jazzmin Admin UI Settings ==========
JAZZMIN_SETTINGS = {
    "site_title": "SafeClick Admin",
    "site_header": "SafeClick",
    "site_brand": "SafeClick Dashboard",
    "welcome_sign": "مركز إدارة SafeClick للتأمين الرقمي",
    "copyright": "SafeClick Ltd",
    "search_model": ["accounts.User", "scans.Scan"],
    "show_ui_builder": False,
    
    "topmenu_links": [
        {"name": "Home",  "url": "admin:index", "permissions": ["auth.view_user"]},
        {"name": "Support", "url": "https://github.com/", "new_window": True},
    ],
    
    # Sections to display and custom icons
    "icons": {
        "accounts.User": "fas fa-users",
        "scans.Scan": "fas fa-shield-alt",
        "scans.Link": "fas fa-link",
        "scans.Blacklist": "fas fa-ban",
        "reports.Report": "fas fa-flag",
        "reports.ReportComment": "fas fa-comments",
        "auth.Group": "fas fa-users-cog",
    },
    
    # Custom dashboard config
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",
    "related_modal_active": False,
    "custom_css": None,
    "custom_js": None,
}

JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-dark",
    "accent": "accent-primary",
    "navbar": "navbar-dark",
    "no_navbar_border": False,
    "navbar_fixed": True,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_fixed": True,
    "sidebar": "sidebar-dark-primary",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": True,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "darkly", # A modern dark theme that fits security apps
    "dark_mode_theme": "darkly",
    "button_classes": {
        "primary": "btn-outline-primary",
        "secondary": "btn-outline-secondary",
        "info": "btn-info",
        "warning": "btn-warning",
        "danger": "btn-danger",
        "success": "btn-success"
    }
}