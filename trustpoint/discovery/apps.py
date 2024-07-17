from django.apps import AppConfig

from discovery.mdns import TrustpointMDNSResponder

class DiscoveryConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'discovery'

    mdns = None

    def ready(self) -> None:
        self.mdns = TrustpointMDNSResponder()