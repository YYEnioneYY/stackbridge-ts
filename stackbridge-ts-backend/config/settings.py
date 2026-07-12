from pathlib import Path

from decouple import Csv, config


def cast_debug(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on", "debug", "development"}


BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config("SECRET_KEY")
DEBUG = config("DEBUG", default=False, cast=cast_debug)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1", cast=Csv())
INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.staticfiles", "rest_framework", "drf_spectacular",
    "apps.auth_service.apps.AuthServiceConfig", "apps.profile_service.apps.ProfileServiceConfig",
    "apps.access_service.apps.AccessServiceConfig", "apps.business_service.apps.BusinessServiceConfig",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware", "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware", "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware", "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql", "NAME": config("DB_NAME"), "USER": config("DB_USER"),
    "PASSWORD": config("DB_PASSWORD"), "HOST": config("DB_HOST", default="localhost"),
    "PORT": config("DB_PORT", default=5432, cast=int),
}}
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
JWT_ACCESS_SECRET = config("JWT_ACCESS_SECRET")
JWT_REFRESH_SECRET = config("JWT_REFRESH_SECRET")
JWT_ALGORITHM = config("JWT_ALGORITHM", default="HS256")
JWT_ACCESS_TTL_MINUTES = config("JWT_ACCESS_TTL_MINUTES", default=15, cast=int)
JWT_REFRESH_TTL_DAYS = config("JWT_REFRESH_TTL_DAYS", default=30, cast=int)
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["apps.auth_service.authentication.JWTAuthentication"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.common.exceptions.api_exception_handler",
}
SPECTACULAR_SETTINGS = {
    "TITLE": "Stackbridge Authentication and Authorization API", "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False, "SECURITY": [{"bearerAuth": []}],
    "APPEND_COMPONENTS": {"securitySchemes": {"bearerAuth": {
        "type": "http", "scheme": "bearer", "bearerFormat": "JWT",
    }}},
}
