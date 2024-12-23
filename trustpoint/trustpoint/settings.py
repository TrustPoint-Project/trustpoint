"""Django settings for trustpoint project.

Generated by 'django-admin startproject' using Django 5.0.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

import os
from pathlib import Path
from django.utils.translation import gettext_lazy as _
from django.core.management.utils import get_random_secret_key

from log.config import logging_config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
ADMIN_ENABLED = True if DEBUG else False

# SECURITY WARNING: keep the secret key used in production secret!
if DEBUG:
    SECRET_KEY = 'DEV-ENVIRON-SECRET-KEY-lh2rw0b0z$s9e=!4see)@_8ta_up&ad&m01$i+g5z@nz5u$0wi'
else:
    # TODO(AlexHx8472): Use proper docker secrets handling.
    SECRET_KEY = Path('/etc/trustpoint/secrets/django_secret_key.env').read_text()

ALLOWED_HOSTS = ['*']

# mDNS service discovery advertisement
ADVERTISED_HOST = '127.0.0.1'
ADVERTISED_PORT = 443

DOCKER_CONTAINER = False

# Application definition

INSTALLED_APPS = [
    'setup_wizard.apps.SetupWizardConfig',
    'users.apps.UsersConfig',
    'home.apps.HomeConfig',
    'devices.apps.DevicesConfig',
    'log.apps.LogConfig',
    'discovery.apps.DiscoveryConfig',
    'onboarding.apps.OnboardingConfig',
    'pki.apps.PkiConfig',
    'sysconf.apps.SysconfConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'crispy_forms',
    'crispy_bootstrap5',
    'django_tables2',
    'ninja',
    # TODO(Aircoookie): Required only for HTTPS testing with Django runserver_plus, remove for production
    'django_extensions',
    # use "python manage.py runserver_plus 8000 --cert-file ../tests/data/x509/https_server.crt
    # --key-file ../tests/data/x509/https_server.pem" to run with HTTPS
    # note: replaces default exception debug page with worse one
    'taggit',
    'django_filters',
    # ensure startup is the last app in the list so that ready() is called after all other apps are initialized
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'trustpoint.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / Path('trustpoint/templates')],
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

WSGI_APPLICATION = 'trustpoint.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20
        }
    },
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

LANGUAGES = [
    ("de", _("German")),
    ("en", _("English")),
]

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

LOCALE_PATHS = [BASE_DIR / Path('trustpoint/locale')]


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

MEDIA_ROOT = BASE_DIR / Path('media')
MEDIA_URL = '/media/'

STATICFILES_DIRS = [BASE_DIR / Path('static')]

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


CRISPY_ALLOWED_TEMPLATE_PACKS = 'bootstrap5'

CRISPY_TEMPLATE_PACK = 'bootstrap5'

# Default django-tables2 template
DJANGO_TABLES2_TEMPLATE = 'django_tables2/bootstrap5.html'
DJANGO_TABLES2_TABLE_ATTRS = {'class': 'table', 'td': {'class': 'v-middle'}}

LOGIN_REDIRECT_URL = 'home:dashboard'
LOGIN_URL = 'users:login'

DJANGO_LOG_LEVEL = 'INFO'

LOGGING = logging_config

TAGGIT_CASE_INSENSITIVE = True

STATIC_ROOT = Path(__file__).parent.parent / Path('collected_static')
