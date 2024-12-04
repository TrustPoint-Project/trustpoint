import logging
import os
import signal

from django.apps import AppConfig


class SetupWizardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'setup_wizard'

    logger: logging.Logger

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('tp').getChild('setup_wizard').getChild(self.__class__.__name__)
        super().__init__(*args, **kwargs)

    def ready(self) -> None:
        """Django startup hook, log startup and shutdown."""
        super().ready()

        from .startup import StartupTaskManager

        dev = StartupTaskManager.running_dev_server()
        wsgi = StartupTaskManager.running_wsgi_server()

        if not dev and not wsgi:
            # Just helper process, not running startup code
            return

        env = 'wsgi' if wsgi else 'dev'
        self.logger.info(f'--- Trustpoint Server Startup ({env}) ---')

        # Register signal handler only if mod_wsgi is not active
        if 'mod_wsgi' not in os.environ.get('SERVER_SOFTWARE', ''):
            original_sigint_handler = signal.getsignal(signal.SIGINT)

            def handle_exit(signum, frame):
                self.logger.info("--- Trustpoint Server Shutdown (SIGINT) ---")
                StartupTaskManager.handle_shutdown_tasks()

                if callable(original_sigint_handler):
                    original_sigint_handler(signum, frame)

            signal.signal(signal.SIGINT, handle_exit)

            original_sigterm_handler = signal.getsignal(signal.SIGTERM)

            def handle_term(signum, frame):
                self.logger.info("--- Trustpoint Server Shutdown (SIGTERM) ---")
                StartupTaskManager.handle_shutdown_tasks()

                if callable(original_sigterm_handler):
                    original_sigterm_handler(signum, frame)

            signal.signal(signal.SIGTERM, handle_term)

        StartupTaskManager.handle_startup_tasks()
