"""
Django settings for siemrules project.

Generated by 'django-admin startproject' using Django 5.0.6.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

import copy
import logging
import os
from pathlib import Path
from textwrap import dedent
import sys
import uuid
import stix2


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET', "insecure_django_secret")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', False)

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', "localhost 127.0.0.1 [::1]").split()

#CORS_ALLOW_ALL_ORIGINS = os.environ.get('DJANGO_CORS_ALLOW_ALL_ORIGINS', True)
#CORS_ALLOWED_ORIGINS = [os.environ.get('DJANGO_CORS_ALLOWED_ORIGINS', "http://127.0.0.1:8001")]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    "corsheaders",
    "rest_framework",
    'dogesec_commons.objects',
    "drf_spectacular",
    'django.contrib.postgres',
    "siemrules.siemrules",
    'django_cleanup.apps.CleanupConfig',
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",

    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "siemrules.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "siemrules.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB'),            # Database name
        'USER': os.getenv('POSTGRES_USER'),          # Database user
        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),  # Database password
        'HOST': os.getenv('POSTGRES_HOST'),          # PostgreSQL service name in Docker Compose
        'PORT': os.getenv('POSTGRES_PORT', '5432'),  # PostgreSQL default port
    },
    
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = "/var/www/staticfiles/"

MEDIA_ROOT = "/var/www/mediafiles/"
MEDIA_URL = "uploads/"

# cache

CELERY_BROKER_URL = os.environ["CELERY_BROKER_URL"]

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': CELERY_BROKER_URL,  # Use the appropriate Redis server URL
        'OPTIONS': {
            # 'CLIENT_CLASS': 'django.core.cache.backends.redis.RedisCacheClient',
        }
    }
}

# Storage

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

if os.getenv("USE_S3_STORAGE") == "1":
    options = {
        "bucket_name": os.environ["R2_BUCKET_NAME"],
        "endpoint_url": os.environ["R2_ENDPOINT_URL"],
        "access_key": os.environ["R2_ACCESS_KEY"],
        "secret_key": os.environ["R2_SECRET_KEY"],
        'custom_domain': os.environ["R2_CUSTOM_DOMAIN"],
        'location': 'feed',
    }
    STORAGES["default"] = {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": options,
    }
    STORAGES["staticfiles"] = {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": {**options, 'location':'django/staticfiles'},
    }

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    # YOUR SETTINGS
    "DEFAULT_SCHEMA_CLASS": "siemrules.siemrules.autoschema.AutoSchema",
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    'EXCEPTION_HANDLER': "dogesec_commons.utils.custom_exception_handler",
}


SPECTACULAR_SETTINGS = {
    "TITLE": "SIEM Rules API",
    "DESCRIPTION": dedent(
        """
        SIEM Rules takes reports containing threat intelligence and turns them into detection rules.\n\n
        [DOGESEC](https://www.dogesec.com/) offer a fully hosted web version of SIEM Rules which includes many additional features over those in this codebase. [You can find out more about the web version here](https://www.siemrules.com/)
        """
    ),
    "VERSION": "1.0.0",
    "CONTACT": {
        "email": "noreply@dogesec.com",
        "url": "https://github.com/muchdogesec/siemrules",
    },
    "TAGS": [
        {"name": "Files", "description": "Upload files and retrieve uploaded files"},
        {"name": "Reports", "description": "Search and retrieve Reports created from uploaded files"},
        {"name": "Rules", "description": "Search and retrieve Rules created from uploaded files"},
        {"name": "Jobs", "description": "Check the status of data retrieval from files"},
        {"name": "Objects", "description": "Search through all STIX objects"},
    ],
    'COMPONENT_SPLIT_REQUEST': True,
    'ENUM_GENERATE_CHOICE_DESCRIPTION': False,
}

STIX_NAMESPACE = uuid.UUID("8ef05850-cb0d-51f7-80be-50e4376dbe63")
STIX_IDENTITY  = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--8ef05850-cb0d-51f7-80be-50e4376dbe63",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "siemrules",
    "description": "https://github.com/muchdogesec/siemrules",
    "identity_class": "system",
    "sectors": [
        "technology"
    ],
    "contact_information": "https://www.dogesec.com/contact/",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}


ARANGODB_DATABASE   = "siemrules"
VIEW_NAME = ARANGODB_DATABASE+"_view"
ARANGODB_COLLECTION = "siemrules"
ARANGODB_USERNAME   = os.getenv('ARANGODB_USERNAME')
ARANGODB_PASSWORD   = os.getenv('ARANGODB_PASSWORD')
ARANGODB_HOST_URL   = os.getenv("ARANGODB_HOST_URL")

MAXIMUM_PAGE_SIZE = int(os.getenv("MAX_PAGE_SIZE", 50))
DEFAULT_PAGE_SIZE = int(os.getenv("DEFAULT_PAGE_SIZE", 50))
GOOGLE_VISION_API_KEY = os.getenv("GOOGLE_VISION_API_KEY")
if not GOOGLE_VISION_API_KEY:
    logging.warning("GOOGLE_VISION_API_KEY not set")

INPUT_TOKEN_LIMIT = int(os.environ["INPUT_TOKEN_LIMIT"])