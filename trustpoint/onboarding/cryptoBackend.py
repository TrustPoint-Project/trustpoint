# Just a placeholder, this should be moved to a more appropriate location and contents adapted

import hashlib
import hmac


class CryptoBackend:
    def pbkdf2_hmac_sha256(hexpass, hexsalt, message=b'', iterations=1000000, dklen=32):
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass, 'utf-8'), bytes(hexsalt, 'utf-8'), iterations, dklen)
        h = hmac.new(pkey, message, hashlib.sha256)
        return h.hexdigest()

    def get_trust_store():
        # TODO: server certificate location must be configurable
        with open('../tests/data/x509/https_server.crt', 'r') as certfile:
            return certfile.read()
        return "It's a Truststore baby."
