from enum import Enum

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend

from django.db import models

class KeyAlgorithm(Enum):
    RSA2048 = 'RSA2048'
    RSA4096 = 'RSA4096'
    SECP256R1 = 'SECP256R1'
    SECP384R1 = 'SECP384R1'
    SECP521R1 = 'SECP521R1'

class AutoGenPkiKeyAlgorithm(models.TextChoices):
    RSA2048 = 'RSA2048', 'RSA2048'
    RSA4096 = 'RSA4096', 'RSA4096'
    SECP256R1 = 'SECP256R1', 'SECP256R1'
    # omitting the rest of the choices as an example that Auto Gen PKI doesn't have to support all key algorithms

    def to_key_algorithm(self) -> KeyAlgorithm:
        return KeyAlgorithm[self]

class KeyGenerator():
    def __init__(self, algorithm: KeyAlgorithm):
        self._algorithm = algorithm

    def generate_key(self):
        """Generates a private key."""
        match self._algorithm:
            case KeyAlgorithm.SECP256R1:
                key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
            case KeyAlgorithm.SECP384R1:
                key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
            case KeyAlgorithm.SECP521R1:
                key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())
            case KeyAlgorithm.RSA2048:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            case KeyAlgorithm.RSA4096:
                key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            case _:  # Invalid algorithm
                raise ValueError("Unsupported key algorithm type")

        return key