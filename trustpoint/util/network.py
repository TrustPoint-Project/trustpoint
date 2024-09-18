"""Network utility functions."""

import socket

# cm. https://stackoverflow.com/a/28950776/
def get_local_ip():
    """Gets the default routable IP address of the server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # arbitrary private IP
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip
