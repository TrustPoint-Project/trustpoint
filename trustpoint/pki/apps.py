import os

from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self) -> None:
        import pki.signals
