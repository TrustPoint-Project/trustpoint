"""Django apps"""
from django.apps import AppConfig


class SysconfConfig(AppConfig):
    """SysConfig App"""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sysconf'

    def ready(self) -> None:
        """Ensure security level update signals are imported"""
        import sysconf.signals  # noqa: F401
