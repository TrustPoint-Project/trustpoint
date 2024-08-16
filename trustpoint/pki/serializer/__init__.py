"""The serializer package provides Serializer classes for serializing and loading pki ASN.1 and similar objects.

Inheritance Diagram
-------------------

.. uml::

    skinparam linetype ortho
    set separator none

    package pki.serializer {
        abstract class Serializer
        class CertificateSerializer
        class PublicKeySerializer
        class PrivateKeySerializer
        class CertificateCollectionSerializer
        class CredentialSerializer
    }

    Serializer <|-- CertificateSerializer
    Serializer <|-- PublicKeySerializer
    Serializer <|-- PrivateKeySerializer
    Serializer <|--- CertificateCollectionSerializer
    Serializer <|--- CredentialSerializer

API Documentation
-----------------

.. Note::

    The python cryptography library is used in this module with the following types utilized.

    The x509 module is the following from the cryptography library:

    - cryptography.x509

    PrivateKey (typing.Union) is on of the types:

    - cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    - cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    - cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey
    - cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey

    PublicKey (typing.Union) is one of the types:

    - cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    - cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
    - cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey
    - cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
"""


from __future__ import annotations


from .base import Serializer
from .key import PublicKeySerializer, PrivateKeySerializer
from .certificate import CertificateSerializer, CertificateCollectionSerializer
from .credential import CredentialSerializer


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


__all__ = [
    'Serializer',
    'CertificateSerializer',
    'CertificateCollectionSerializer',
    'PublicKeySerializer',
    'PrivateKeySerializer',
    'CredentialSerializer'
]
