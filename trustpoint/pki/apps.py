import os

from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self):
        if not os.environ.get('TRUSTPOINT_RUNNING'):
            # Just helper process, not running startup code
            return

        import pki.signals
