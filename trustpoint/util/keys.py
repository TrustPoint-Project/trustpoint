from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

#from core.oid import EllipticCurveOid, PublicKeyAlgorithmOid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from django.db import models

if TYPE_CHECKING:
    from pki.models import CertificateModel


class SignatureSuite(Enum):

    RSA2048 = 'RSA2048SHA256'
    RSA3072 = 'RSA3072SHA256'
    RSA4096 = 'RSA4096SHA256'
    SECP256R1 = 'SECP256R1SHA256'
    SECP384R1 = 'SECP384R1SHA384'

    @classmethod
    def get_signature_suite_by_public_key(
            cls, public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> SignatureSuite:
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size == 2048:
                return cls.RSA2048
            if public_key.key_size == 3072:
                return cls.RSA3072
            if public_key.key_size == 4096:
                return cls.RSA4096
            raise ValueError

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(public_key.curve, ec.SECP256R1):
                return cls.SECP256R1
            if isinstance(public_key.curve, ec.SECP384R1):
                return cls.SECP384R1
            raise ValueError

        raise ValueError


class AutoGenPkiKeyAlgorithm(models.TextChoices):
    RSA2048 = 'RSA2048SHA256', 'RSA2048'
    RSA4096 = 'RSA4096SHA256', 'RSA4096'
    SECP256R1 = 'SECP256R1', 'SECP256R1'
    # omitting the rest of the choices as an example that Auto Gen PKI doesn't have to support all key algorithms

    def to_key_algorithm(self) -> SignatureSuite:
        return SignatureSuite(str(self))

class KeyGenerator:
    def __init__(self, algorithm: SignatureSuite):
        self._algorithm = algorithm

    def generate_key(self):
        """Generates a private key."""
        match self._algorithm:
            case SignatureSuite.SECP256R1:
                key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
            case SignatureSuite.SECP384R1:
                key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
            case SignatureSuite.RSA2048:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            case SignatureSuite.RSA2048:
                key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
            case SignatureSuite.RSA4096:
                key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            case _:  # Invalid algorithm
                raise ValueError("Unsupported key algorithm type")

        return key
