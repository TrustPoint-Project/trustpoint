"""Django apps module which defines the app configuration."""

from django.apps import AppConfig


class DevicesConfig(AppConfig):
    """Devices app configuration."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'devices'

    def ready(self) -> None:
        """Django startup hook"""

        import devices.signals
