"""Django apps module which defines the app configuration."""


from django.apps import AppConfig


class PkiConfig(AppConfig):
    """Pki app configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'
