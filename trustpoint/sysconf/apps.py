"""Django apps"""
from django.apps import AppConfig


class SysconfConfig(AppConfig):
    """SysConfig App"""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sysconf'

    def ready(self):
        import sysconf.signals  # Stelle sicher, dass die Signale importiert werden
