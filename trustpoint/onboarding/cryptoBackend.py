# Just a placeholder, this should be moved to a more appropriate location and contents adapted

import hashlib
import hmac

class CryptoBackend:
    def pbkdf2_hmac_sha256(hexpass, hexsalt, message=b'', iterations=1000000, dklen=32):
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass,'utf-8'), bytes(hexsalt,'utf-8'), iterations, dklen)
        h = hmac.new(pkey, message, hashlib.sha256)
        return h.hexdigest()
    
    def get_trust_store():
        return "It's a Truststore baby."