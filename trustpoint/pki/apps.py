from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self):
        import pki.signals

        from .tasks import start_crl_generation_thread
        start_crl_generation_thread()
