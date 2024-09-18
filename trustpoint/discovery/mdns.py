"""mDNS responder for trustpoint discovery."""

import argparse
import logging
import socket
from time import sleep

from zeroconf import IPVersion, ServiceInfo, Zeroconf
from util.network import get_local_ip

log = logging.getLogger('tp.discovery')

class TrustpointMDNSResponder:
    #desc =W {"path": "/test/"}

    def __init__(self):
        """Initialize the TrustpointMDNSResponder."""

        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.info = ServiceInfo(
            "_http._tcp.local.",
            "trustpoint._http._tcp.local.",
            # TODO(Air): Do not hardcode IP + port
            # get_local_ip() works, but only for IPv4 without NAT
            addresses=[socket.inet_aton("127.0.0.1"),
                       #socket.inet_aton(get_local_ip())
                      ],
            port=443, # TODO: Do not hardcode port
            #properties=desc,
            server="tp.local.",
        )
        self.register()

    def register(self):
        """Register the trustpoint service with mDNS."""

        try:
            log.info("Registering trustpoint service with mDNS")
            self.unregister()
            self.zeroconf.register_service(self.info)
        except Exception as e:
            log.exception("Failed to register mDNS service")

    def unregister(self):
        """Unregister the trustpoint service with mDNS."""
        self.zeroconf.unregister_service(self.info)

    def __del__(self):
        self.unregister()
        self.zeroconf.close()
