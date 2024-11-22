"""App configuration for the startup app."""

from django.apps import AppConfig

import logging
import signal

log = logging.getLogger('tp')

class StartupConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'startup'

    def ready(self) -> None:
        """Django startup hook, log startup and shutdown."""
        super().ready()

        from .startup import StartupTaskManager

        dev = StartupTaskManager.running_dev_server()
        wsgi = StartupTaskManager.running_wsgi_server()

        if not dev and not wsgi:
            # Just helper process, not running startup code
            return
    
        log.info(f'--- Trustpoint Server Startup ({'wsgi' if wsgi else 'dev'}) ---')

        original_sigint_handler = signal.getsignal(signal.SIGINT)

        def handle_exit(signum, frame):
            log.info("--- Trustpoint Server Shutdown (SIGINT) ---")
            StartupTaskManager.handle_shutdown_tasks()

            if callable(original_sigint_handler):
                original_sigint_handler(signum, frame)

        signal.signal(signal.SIGINT, handle_exit)

        original_sigterm_handler = signal.getsignal(signal.SIGTERM)

        def handle_term(signum, frame):
            log.info("--- Trustpoint Server Shutdown (SIGTERM) ---")
            StartupTaskManager.handle_shutdown_tasks()

            if callable(original_sigterm_handler):
                original_sigterm_handler(signum, frame)

        signal.signal(signal.SIGTERM, handle_term)

        StartupTaskManager.handle_startup_tasks()
