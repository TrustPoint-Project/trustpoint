import os

from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self):
        if not os.environ.get('RUN_MAIN') and not os.environ.get('WERKZEUG_RUN_MAIN'):
            # Just helper process, not running startup code
            return

        import pki.signals
