from __future__ import annotations
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from core.oid import PublicKeyAlgorithmOid, EllipticCurveOid

from django.db import models

from typing import TYPE_CHECKING

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
    
    @classmethod
    def get_hash_algorithm_by_key(
        cls, key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey
              | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> hashes.HashAlgorithm:
        """Returns the hash algorithm based on the public or private key type

        SHA384 is used for EC keys with the SECP384R1 curve, otherwise SHA256 is used.
        """
        if isinstance(key, ec.EllipticCurvePublicKey) or isinstance(key, ec.EllipticCurvePrivateKey):
            if isinstance(key.curve, ec.SECP384R1):
                return hashes.SHA384()
            
        return hashes.SHA256()
    
    @classmethod
    def get_signature_suite_from_cert_type(cls, cert: CertificateModel) -> SignatureSuite:
        if cert.spki_algorithm_oid == PublicKeyAlgorithmOid.RSA.value:
            if cert.spki_key_size == 2048:
                return cls.RSA2048
            elif cert.spki_key_size == 3072:
                return cls.RSA3072
            elif cert.spki_key_size == 4096:
                return cls.RSA4096
            else:
                raise ValueError
        elif cert.spki_algorithm_oid == PublicKeyAlgorithmOid.ECC.value:
            if cert.spki_ec_curve_oid == EllipticCurveOid.SECP256R1.value:
                return cls.SECP256R1
            elif cert.spki_ec_curve_oid == EllipticCurveOid.SECP384R1.value:
                return cls.SECP384R1
            else:
                raise ValueError
        else:
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
    
class DigitalSignature:
    """A class that uses an appropriate digital signature algorithm based on the key type.
    
    Uses the RSA-PKCS1.5 signature scheme for RSA keys and ECDSA for EC keys."""

    @staticmethod
    def sign(data: bytes, private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.sign(
                data,
                padding=padding.PKCS1v15(),
                # padding.PSS(
                #     mgf=padding.MGF1(hashes.SHA256()),
                #     salt_length=padding.PSS.MAX_LENGTH
                # ),
                algorithm=hashes.SHA256()
            )
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            if isinstance(private_key.curve, ec.SECP256R1):
                return private_key.sign(data, signature_algorithm=ec.ECDSA(hashes.SHA256()))
            if isinstance(private_key.curve, ec.SECP384R1):
                return private_key.sign(data, signature_algorithm=ec.ECDSA(hashes.SHA384()))
            raise ValueError
        
        raise ValueError
    
    @staticmethod
    def verify(signature: bytes, data: bytes, public_key: CertificatePublicKeyTypes) -> None:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding=padding.PKCS1v15(),
                # padding.PSS(
                #     mgf=padding.MGF1(hashes.SHA256()),
                #     salt_length=padding.PSS.MAX_LENGTH
                # ),
                algorithm=hashes.SHA256()
            )
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(public_key.curve, ec.SECP256R1):
                public_key.verify(signature, data, signature_algorithm=ec.ECDSA(hashes.SHA256()))
                return
            if isinstance(public_key.curve, ec.SECP384R1):
                public_key.verify(signature, data, signature_algorithm=ec.ECDSA(hashes.SHA384()))
                return
            raise ValueError
        
        raise ValueError