import sys

from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self):
        if 'runserver' not in sys.argv and 'shell' not in sys.argv:
            return

        import pki.signals

        from .tasks import start_crl_generation_thread
        start_crl_generation_thread()
