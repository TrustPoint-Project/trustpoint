import logging
import signal
import os

from django.apps import AppConfig

from discovery.mdns import TrustpointMDNSResponder

log = logging.getLogger('tp.discovery')

class DiscoveryConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'discovery'

    mdns = None

    def ready(self) -> None:

        """Django startup hook, handle startup and shutdown."""
        super().ready()

        if not os.environ.get('TRUSTPOINT_RUNNING'):
            # Just helper process, not running startup code
            return
    
        self.mdns = TrustpointMDNSResponder()

        original_sigint_handler = signal.getsignal(signal.SIGINT)

        def handle_exit(signum, frame):
            self.mdns.unregister()

            if callable(original_sigint_handler):
                original_sigint_handler(signum, frame)

        signal.signal(signal.SIGINT, handle_exit)

        original_sigterm_handler = signal.getsignal(signal.SIGTERM)

        def handle_term(signum, frame):
            self.mdns.unregister()

            if callable(original_sigterm_handler):
                original_sigterm_handler(signum, frame)

        signal.signal(signal.SIGTERM, handle_term)
