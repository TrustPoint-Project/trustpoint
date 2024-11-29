"""Django apps module which defines the app configuration."""


from django.apps import AppConfig


class DevicesConfig(AppConfig):
    """Devices app configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'devices_deprecated'

    def ready(self):
        import devices_deprecated.signals
