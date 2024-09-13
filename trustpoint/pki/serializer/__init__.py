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


from .base import PrivateKey, PublicKey, Serializer
from .key import PrivateKeySerializer, PublicKeySerializer
from .certificate import CertificateCollectionSerializer, CertificateSerializer
from .credential import CredentialSerializer

__all__ = [
    'PublicKey',
    'PrivateKey',
    'Serializer',
    'CertificateSerializer',
    'CertificateCollectionSerializer',
    'PublicKeySerializer',
    'PrivateKeySerializer',
    'CredentialSerializer',
]
