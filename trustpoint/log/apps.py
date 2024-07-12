"""Configuration for the log app."""

import logging
import signal
from django.apps import AppConfig

log = logging.getLogger('tp')

class LogConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log'

    def ready(self) -> None:
        """Django startup hook, log startup and shutdown."""
        super().ready()
    
        log.info('--- Trustpoint Server Startup ---')

        original_sigint_handler = signal.getsignal(signal.SIGINT)

        def handle_exit(signum, frame):
            log.info("--- Trustpoint Server Shutdown (SIGINT) ---")

            if callable(original_sigint_handler):
                original_sigint_handler(signum, frame)

        signal.signal(signal.SIGINT, handle_exit)

        original_sigterm_handler = signal.getsignal(signal.SIGTERM)

        def handle_term(signum, frame):
            log.info("--- Trustpoint Server Shutdown (SIGTERM) ---")

            if callable(original_sigterm_handler):
                original_sigterm_handler(signum, frame)

        signal.signal(signal.SIGTERM, handle_term)
