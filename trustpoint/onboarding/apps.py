"""Django apps module which defines the app configuration."""

from django.apps import AppConfig


class OnboardingConfig(AppConfig):
    """Onboarding app configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'onboarding'
