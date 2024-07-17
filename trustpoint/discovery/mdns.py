"""mDNS responder for trustpoint discovery."""

import argparse
import logging
import socket
from time import sleep

from zeroconf import IPVersion, ServiceInfo, Zeroconf

class TrustpointMDNSResponder:
    #desc =W {"path": "/test/"}

    def __init__(self):
        """Initialize the TrustpointMDNSResponder."""

        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.info = ServiceInfo(
            "_http._tcp.local.",
            "trustpoint._http._tcp.local.",
            # TODO(Air): How to add the actual IP address here?
            # This could be tricky in case of multiple interfaces
            addresses=[socket.inet_aton("127.0.0.1")],
            port=80,
            #properties=desc,
            server="tp.local.",
        )
        self.register()

    def register(self):
        """Register the trustpoint service with mDNS."""

        print("Registration of mDNS service...")
        self.zeroconf.unregister_service(self.info)
        self.zeroconf.register_service(self.info)

    def __del__(self):
        print("Destructor called, TrustpointMDNSResponder deleted.")
        self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()