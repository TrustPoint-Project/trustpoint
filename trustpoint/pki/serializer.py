"""The serializer module provides Serializer classes for serializing and loading pki ASN.1 objects.

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

import abc
from typing import Union, get_args

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs7, pkcs12

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.

    **Serializer UML Class Diagram**

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class abc.ABC
        abstract class Serializer

        abc.ABC <|-- Serializer
    """

    # @abc.abstractmethod
    # def __str__(self) -> str:
    #     pass
    #
    # @abc.abstractmethod
    # def __repr__(self) -> str:
    #     pass
    #
    # @abc.abstractmethod
    # def load(self, data: bytes) -> bytes:
    #     pass


class CertificateSerializer(Serializer):
    """The CertificateSerializer class provides methods for serializing and loading a certificate.

    Warnings:
        The CertificateSerializer class does not evaluate or validate any contents of the certificate.

    **CertificateSerializer UML Class Diagram**

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer

        class CertificateSerializer {
            -_certificate: x509.Certificate
            --
            +<<create>> CertificateSerializer(certificate)
            {static} +<<create>> from_crypto(certificate)
            {static} +<<create>> from_bytes(certificate_data)
            {static} +<<create>> from_string(certificate_data)

            +as_der() : bytes
            +as_crypto() : x509.Certificate

            {static} -_load_pem_certificate(certificate_data) : x509.Certificate
            {static} -_load_der_certificate(certificate_data) : x509.Certificate
        }

        Serializer <|-- CertificateSerializer
    """

    _certificate: x509.Certificate

    def __init__(self, certificate: x509.Certificate) -> None:
        """Inits the CertificateSerializer class.

        Args:
            certificate: The certificate to serialize.

        Raises:
            TypeError: If the certificate is not a x509.Certificate instance.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError('Certificate must be an instance of x509.Certificate.')

        self._certificate = certificate

    @classmethod
    def from_crypto(cls, certificate: x509.Certificate) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a x509.Certificate instance.

        Args:
            certificate: The certificate to serialize.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            TypeError: If the certificate is not a x509.Certificate instance.
        """
        return cls(certificate)

    @classmethod
    def from_bytes(cls, certificate_data: bytes) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a bytes object.

        Args:
            certificate_data: Bytes that contains a certificate in either DER or PEM format.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            ValueError: If loading of the certificate from bytes failed.
        """
        try:
            return cls(cls._load_pem_certificate(certificate_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_der_certificate(certificate_data))
        except ValueError:
            pass

        raise ValueError('Failed to load certificate. May be malformed or not in a DER or PEM format.')

    @classmethod
    def from_string(cls, certificate_data: str) -> CertificateSerializer:
        """Inits the CertificateSerializer class from a string object.

        Args:
            certificate_data: String that contains a certificate in PEM format.

        Returns:
            CertificateSerializer: CertificateSerializer instance.

        Raises:
            ValueError: If loading of the certificate from string failed.
        """
        return cls.from_bytes(certificate_data.encode())

    def as_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PEM format.

        Returns:
            bytes: Bytes that contains the certificate in PEM format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

    def as_der(self) -> bytes:
        """Gets the associated certificate as bytes in DER format.

        Returns:
            bytes: Bytes that contains the certificate in DER format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.DER)

    def as_crypto(self) -> x509.Certificate:
        """Gets the associated certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The associated certificate as x509.Certificate instance.
        """
        return self._certificate

    @staticmethod
    def _load_pem_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(certificate_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @staticmethod
    def _load_der_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(certificate_data)
        except Exception:   # noqa: BLE001
            raise ValueError


class PublicKeySerializer(Serializer):
    """The PublicKeySerializer class provides methods for serializing and loading a public key.

    Warnings:
        The PublicKeySerializer class does not evaluate or validate any contents of the public key.

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer
        class PublicKeySerializer {
            -_public_key: PublicKey
            --
            +<<create>> PublicKeySerializer(public_key)
            {static} +<<create>> from_crypto(public_key)
            {static} +<<create>> from_bytes(public_key_data)
            {static} +<<create>> from_string(public_key_data)
            {static} +<<create>> from_private_key(private_key)

            +as_pem() : bytes
            +as_der() : bytes
            +as_crypto() : PublicKey

            {static} -_load_pem_public_key(public_key_data) : PublicKey
            {static} -_load_der_public_key(public_key_data) : PublicKey
        }

        Serializer <|-- PublicKeySerializer
    """

    _public_key: PublicKey

    def __init__(self, public_key: PublicKey) -> None:
        """Inits the PublicKeySerializer class.

        Args:
            public_key: The public key to serialize (rsa, ec, ed448 or ed25519).

        Raises:
            TypeError: If the public key is not a PublicKey object.
        """
        if not isinstance(public_key, get_args(PublicKey)):
            raise TypeError('PublicKey must be an instance of PublicKey.')

        self._public_key = public_key

    @classmethod
    def from_crypto(cls, public_key: PublicKey) -> PublicKeySerializer:
        """Inits the PublicKeySerializer class from a PublicKey instance.

        Args:
            public_key: The public key to serialize.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance.

        Raises:
            TypeError: If the public key is not PublicKey instance.
        """
        return cls(public_key)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeySerializer:
        """Inits the PublicKeySerializer class from a PublicKey instance.

        Args:
            private_key: The private key to extract the public key from which shall be serialized.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance.
        """
        return cls(private_key.public_key())

    @classmethod
    def from_bytes(cls, public_key_data: bytes) -> PublicKeySerializer:
        """Inits the PublicKeySerializer class from a bytes object.

        Args:
            public_key_data: Bytes that contains a public key in PEM or DER format.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance.

        Raises:
            ValueError: If loading of the public key from bytes failed.
        """
        try:
            return cls(cls._load_pem_public_key(public_key_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_der_public_key(public_key_data))
        except ValueError:
            pass

        raise ValueError('Failed to load public key. May be malformed or not in a DER or PEM format.')

    @classmethod
    def from_string(cls, public_key_data: str) -> PublicKeySerializer:
        """Inits the PublicKeySerializer class from a string object.

        Args:
            public_key_data: String that contains a public key in PEM format.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance.

        Raises:
            ValueError: If loading of the private key from string failed.
        """
        return cls.from_bytes(public_key_data.encode())

    def as_pem(self) -> bytes:
        """Gets the associated public key as bytes in PEM format.

        Returns:
            bytes: Bytes that contains the public key in PEM format.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def as_der(self) -> bytes:
        """Gets the associated public key as bytes in DER format.

        Returns:
            bytes: Bytes that contains the public key in PEM format.
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def as_crypto(self) -> PublicKey:
        """Gets the associated public key as PublicKey instance.

        Returns:
            PublicKey: The associated private key as PublicKey instance.
        """
        return self._public_key

    @staticmethod
    def _load_pem_public_key(public_key_data: bytes) -> PublicKey:
        try:
            return serialization.load_pem_public_key(public_key_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @staticmethod
    def _load_der_public_key(public_key_data: bytes) -> PublicKey:
        try:
            return serialization.load_der_public_key(public_key_data)
        except Exception:   # noqa: BLE001
            raise ValueError


class PrivateKeySerializer(Serializer):
    """The PrivateKeySerializer class provides methods for serializing and loading a private key.

    Warnings:
        The PrivateKeySerializer class does not evaluate or validate any contents of the private key.

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer
        class PublicKeySerializer
        class PrivateKeySerializer {
            -_private_key: PrivateKey

            -_public_key_serializer_class: type[PublicKeySerializer]
            --
            +<<create>> PrivateKeySerializer(private_key)
            {static} +<<create>> from_crypto(private_key)
            {static} +<<create>> from_bytes(private_key_data, password)
            {static} +<<create>> from_string(private_key_data, password)

            +as_pkcs1_pem(password) : bytes
            +as_pkcs1_der(password) : bytes
            +as_pkcs8_pem(password) : bytes
            +as_pkcs8_der(password) : bytes
            +as_pkcs12(password, friendly_name) : bytes
            +as_crypto() : PrivateKey
            +get_public_key_serializer() : PublicKeySerializer

            {static} -_get_encryption_algorithm(password) : serialization.KeySerializationEncryption
            {static} -_load_pem_private_key(private_key_data, password) : PrivateKey
            {static} -_load_der_private_key(private_key_data, password) : PrivateKey
            {static} -_load_pkcs12_private_key(p12_data, password) : PrivateKey
        }

        Serializer <|-- PrivateKeySerializer
        Serializer <|-- PublicKeySerializer

        PrivateKeySerializer --o PublicKeySerializer
    """

    _private_key: PrivateKey

    _public_key_serializer_class: type[PublicKeySerializer] = PublicKeySerializer

    def __init__(self, private_key: PrivateKey) -> None:
        """Inits the PrivateKeySerializer class.

        Args:
            private_key: The private key to serialize (rsa, ec, ed448 or ed25519).

        Raises:
            TypeError: If the private key is not a PrivateKey object.
        """
        if not isinstance(private_key, get_args(PrivateKey)):
            raise TypeError('private_key must be an instance of PrivateKey.')

        self._private_key = private_key

    @classmethod
    def from_crypto(cls, private_key: PrivateKey) -> PrivateKeySerializer:
        """Inits the PrivateKeySerializer class from a PrivateKey instance.

        Args:
            private_key: The private key to serialize.

        Returns:
            PrivateKeySerializer: PrivateKeySerializer instance.

        Raises:
            TypeError: If the private key is not PrivateKey instance.
        """
        return cls(private_key)

    @classmethod
    def from_bytes(cls, private_key_data: bytes, password: None | bytes = None) -> PrivateKeySerializer:
        """Inits the PrivateKeySerializer class from a bytes object.

        Args:
            private_key_data: Bytes that contains a private key in PEM, DER or PKCS#12 format.
            password: Password as bytes if the private key is encrypted, None otherwise.

        Returns:
            PrivateKeySerializer: PrivateKeySerializer instance.

        Raises:
            ValueError: If loading of the private key from bytes failed.
        """
        try:
            return cls(cls._load_pem_private_key(private_key_data, password))
        except ValueError:
            pass

        try:
            return cls(cls._load_der_private_key(private_key_data, password))
        except ValueError:
            pass

        try:
            return cls(cls._load_pkcs12_private_key(private_key_data, password))
        except ValueError:
            pass

        raise ValueError(
            'Failed to load private key. May be an incorrect password, malformed data or an unsupported format.'
        )

    @classmethod
    def from_string(cls, private_key_data: str, password: None | bytes = None) -> PrivateKeySerializer:
        """Inits the PrivateKeySerializer class from a string object.

        Args:
            private_key_data: String that contains a private key in PEM format.
            password: Password as bytes if the private key is encrypted, None otherwise.

        Returns:
            PrivateKeySerializer: PrivateKeySerializer instance.

        Raises:
            ValueError: If loading of the private key from string failed.
        """
        return cls.from_bytes(private_key_data.encode(), password)

    def as_pkcs1_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 DER format.

        Args:
            password: Password if the private key shall be encrypted, None otherwise.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs1_pem(self, password: None | bytes) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 PEM format.

        Args:
            password: Password if the private key shall be encrypted, None otherwise.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 PEM format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_der(self, password: None | bytes) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password: Password if the private key shall be encrypted, None otherwise.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_pem(self, password: None | bytes) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password: Password if the private key shall be encrypted, None otherwise.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs12(self, password: None | bytes, friendly_name: bytes = b'') -> bytes:
        """Gets the associated private key as bytes in PKCS#12 format.

        Args:
            password: Password if the private key shall be encrypted, None otherwise.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            bytes: Bytes that contains the private key in PKCS#12 format.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._private_key,
            cert=None,
            cas=None,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_crypto(self) -> PrivateKey:
        """Gets the associated private key as PrivateKey instance.

        Returns:
            PrivateKey: The associated private key as PrivateKey instance.
        """
        return self._private_key

    def get_public_key_serializer(self) -> PublicKeySerializer:
        """Gets the PublicKeySerializer instance of the associated private key.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance of the associated private key.
        """
        return self._public_key_serializer_class(self._private_key.public_key())

    @staticmethod
    def _get_encryption_algorithm(password: None | bytes = None) -> serialization.KeySerializationEncryption:
        if password:
            return serialization.BestAvailableEncryption(password)
        return serialization.NoEncryption()

    @staticmethod
    def _load_pem_private_key(private_key_data: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return serialization.load_pem_private_key(private_key_data, password)
        except Exception:   # noqa: BLE001
            raise ValueError

    @staticmethod
    def _load_der_private_key(private_key_data: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return serialization.load_der_private_key(private_key_data, password)
        except Exception:   # noqa: BLE001
            raise ValueError

    @staticmethod
    def _load_pkcs12_private_key(p12_data: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return pkcs12.load_pkcs12(p12_data, password).key
        except Exception:   # noqa: BLE001
            raise ValueError


class CertificateCollectionSerializer(Serializer):
    """The CertificateCollectionSerializer class provides methods for serializing and loading certificate collections.

    Certificate collections are lists of single certificates. The order will be preserved. Usually these collections
    will either be a certificate chain or a trust store.

    Warnings:
        The CertificateCollectionSerializer class does not evaluate or validate any contents of the certificate
        collection, i.e. no certificate chains are validated.

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer
        class CertificateSerializer
        class CertificateCollectionSerializer {
            -_certificate_collection: list[x509.Certificate]
            -_certificate_serializer_class: type[CertificateSerializer]
            --
            +<<create>> CertificateCollectionSerializer(certificate_collection)
            {static} +<<create>> from_crypto(credential_private_key, credential_certificate, additional_certificates)
            {static} +<<create>> from_crypto_pkcs12(p12)
            {static} +<<create>> from_bytes(credential_data, password)
            {static} +<<create>> from_string(certificate_collection_data)
            {static} +<<create>> from_list_of_bytes(certificate_collection_data)
            {static} +<<create>> from_list_of_strings(certificate_collection_data)

            +as_pkcs12(friendly_name, password) : bytes
            +as_crypto() : bytes

            +get_credential_private_key_serializer() : PrivateKeySerializer
            +get_credential_certificate_serializer() : CertificateSerializer
            +get_additional_certificate_serializer() : CertificateCollectionSerializer
            +get_certificate_collection_serializer() : CertificateCollectionSerializer

            {static} -_load_pkcs12(p12_data, password) : pkcs12.PKCS12KeyAndCertificates
        }

        Serializer <|-- CertificateCollectionSerializer
        Serializer <|-- CertificateSerializer
        CertificateCollectionSerializer --o CertificateSerializer
    """

    _certificate_collection: list[x509.Certificate]
    _certificate_serializer_class: type[CertificateSerializer] = CertificateSerializer

    def __init__(self, certificate_collection: list[x509.Certificate]) -> None:
        """Inits the CertificateCollectionSerializer class.

        Args:
            certificate_collection: A list of x509.Certificates representing the collection.

        Raises:
            ValueError: If the list is empty.
            TypeError: If certificate_collection is not a list of x509.Certificates.
        """
        if not isinstance(certificate_collection, list):
            raise TypeError('certificate_collection must be a list of x509.Certificates.')

        if not certificate_collection:
            raise ValueError('certificate_collection must contain at least one x509.Certificate instance.')

        for certificate in certificate_collection:
            if not isinstance(certificate, x509.Certificate):
                raise TypeError('certificate_collection contains at least one element that is not a x509.Certificate.')

        self._certificate_collection = certificate_collection

    @classmethod
    def from_crypto(cls, certificate_collection: list[x509.Certificate]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of x509.Certificate instances.

        Args:
            certificate_collection: A list of x509.Certificates to serialize.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If the list is empty.
            TypeError: If certificate_collection is not a list of x509.Certificates.
        """
        return cls(certificate_collection)

    @classmethod
    def from_crypto_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a pkcs12.PKCS12 instance.

        Args:
            p12: A pkcs12.PKCS12 instance containing the certificate that shall be serialized.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If the pkcs12.PKCS12 instance does not contain any certificates.
        """
        certificates = [p12.cert.certificate]
        certificates.extend([certificate.certificate for certificate in p12.additional_certs])
        return cls(certificates)

    @classmethod
    def from_bytes(
        cls, certificate_collection_data: bytes, password: None | bytes = None
    ) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a bytes object.

        Args:
            certificate_collection_data: Bytes that contain a collection of certificates in
                PEM, PKCS#7 PEM, PKCS#7 DER or PKCS#12 format.
            password: Password as bytes if the content is encrypted, None otherwise.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        try:
            return cls(cls._load_pem(certificate_collection_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_pkcs7_pem(certificate_collection_data))
        except ValueError:
            pass

        try:
            return cls(cls._load_pkcs7_der(certificate_collection_data))
        except ValueError:
            pass

        try:
            p12 = cls._load_pkcs12(certificate_collection_data, password)
            return cls.from_crypto_pkcs12(p12)
        except ValueError:
            pass

        raise ValueError(
            'Failed to load certificate collection. '
            'May be an incorrect password, malformed data or an unsupported format.'
        )

    @classmethod
    def from_string(cls, certificate_collection_data: str) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a string object.

        Args:
            certificate_collection_data: String that contain a collection of certificates in
                PEM or PKCS#7 PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        return cls.from_bytes(certificate_collection_data.encode())

    @classmethod
    def from_list_of_bytes(cls, certificate_collection_data: list[bytes]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of bytes objects.

        Args:
            certificate_collection_data: A list of bytes that contain certificates in DER or PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        try:
            return cls(
                [
                    CertificateSerializer.from_bytes(certificate).as_crypto()
                    for certificate in certificate_collection_data
                ]
            )
        except Exception:   # noqa: BLE001
            raise ValueError(
                'Failed to load certificate collection. '
                'May be an incorrect password, malformed data or an unsupported format.'
            )

    @classmethod
    def from_list_of_strings(cls, certificate_collection_data: list[str]) -> CertificateCollectionSerializer:
        """Inits the CertificateCollectionSerializer class from a list of string objects.

        Args:
            certificate_collection_data: A list of strings that contain certificates in PEM format.

        Returns:
            CertificateCollectionSerializer: CertificateCollectionSerializer instance.

        Raises:
            ValueError: If loading the collection of certificates failed.
        """
        return cls.from_list_of_bytes([cert.encode() for cert in certificate_collection_data])

    def as_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PEM format.
        """
        return b''.join([CertificateSerializer(certificate).as_pem() for certificate in self._certificate_collection])

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates(self._certificate_collection, serialization.Encoding.PEM)

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates(self._certificate_collection, serialization.Encoding.DER)

    def as_crypto(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: List of x509.Certificate instances.
        """
        return self._certificate_collection

    @classmethod
    def _load_pem(cls, pem_data: bytes) -> list[x509.Certificate]:
        try:
            return x509.load_pem_x509_certificates(pem_data)
        except Exception as exception:  # noqa: BLE001
            raise ValueError from exception

    @classmethod
    def _load_pkcs7_pem(cls, p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_pem_pkcs7_certificates(p7_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @classmethod
    def _load_pkcs7_der(cls, p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_der_pkcs7_certificates(p7_data)
        except Exception:   # noqa: BLE001
            raise ValueError

    @classmethod
    def _load_pkcs12(cls, p12_data: bytes, password: None | bytes = None) -> pkcs12.PKCS12KeyAndCertificates:
        try:
            return pkcs12.load_pkcs12(p12_data, password)
        except Exception:   # noqa: BLE001
            raise ValueError


class CredentialSerializer(Serializer):
    """The CredentialSerializer class provides methods for serializing and loading X.509 Credentials.

    These Credentials consist of one private key and the corresponding certificate. Further certificates, like
    the corresponding certificate chain may also be included.

    Warnings:
        The CredentialSerializer class does not evaluate or validate any contents of the credential,
        i.e. neither the certificate chain nor if the private key matches the certificate is validated.

    .. uml::

        skinparam linetype ortho
        set separator none

        abstract class Serializer
        class PrivateKeySerializer
        class CertificateSerializer
        class CertificateCollectionSerializer
        class CredentialSerializer {
            -_credential_private_key: PrivateKey
            -_credential_certificate: x509.Certificate
            -_additional_certificates: list[x509.Certificate]

            _private_key_serializer_class: type[PrivateKeySerializer]
            _certificate_serializer_class: type[CertificateSerializer]
            _certificate_collection_serializer_class: type[CertificateCollectionSerializer]
            --
            +<<create>> CredentialSerializer(credential_private_key, credential_certificate, additional_certificates)
            {static} +<<create>> from_crypto(certificate_collection)
            {static} +<<create>> from_crypto_pkcs12(p12)
            {static} +<<create>> from_bytes(credential_data, password)

            +as_pem() : bytes
            +as_pkcs7_der() : bytes
            +as_pkcs7_pem() : bytes
            +as_crypto() : bytes

            {static} -_get_encryption_algorithm(password) : serialization.KeySerializationEncryption
            {static} -_load_pkcs12(p12_data, password) : pkcs12.PKCS12KeyAndCertificates
        }

        Serializer <|-- PrivateKeySerializer
        Serializer <|-- CertificateSerializer
        Serializer <|-- CertificateCollectionSerializer
        Serializer <|-- CredentialSerializer

        CredentialSerializer --o PrivateKeySerializer
        CredentialSerializer --o CertificateSerializer
        CredentialSerializer --o CertificateCollectionSerializer

    """

    _credential_private_key: PrivateKey
    _credential_certificate: x509.Certificate
    _additional_certificates: list[x509.Certificate]

    _private_key_serializer_class: type[PrivateKeySerializer] = PrivateKeySerializer
    _certificate_serializer_class: type[CertificateSerializer] = CertificateSerializer
    _certificate_collection_serializer_class: type[CertificateCollectionSerializer] = CertificateCollectionSerializer

    def __init__(
        self,
        credential_private_key: PrivateKey,
        credential_certificate: x509.Certificate,
        additional_certificates: None | list[x509.Certificate] = None,
    ) -> None:
        """Inits the CertificateCollectionSerializer class.

        Args:
            credential_private_key: The private key corresponding to the credential (rsa, ec, ed448, ed25519).
            credential_certificate: The certificate corresponding to the private key.
            additional_certificates: Usually only contains the ca certificats (certificate chain).

        Raises:
            TypeError:
                If credential_private_key is not an instance of PrivateKey.
                if credential_certificate is not an instance of x509.Certificate.
                If additional_certificates is not None or and instance of list[x509.Certificate].
        """
        if not isinstance(credential_private_key, get_args(PrivateKey)):
            raise TypeError('credential_private_key must be an instance of PrivateKey.')

        if not isinstance(credential_certificate, x509.Certificate):
            raise TypeError('credential_certificate must be an instance of x509.Certificate.')

        if additional_certificates is None:
            additional_certificates = []

        if not isinstance(additional_certificates, list):
            raise TypeError('additional_certificates must be None or a list of x509.Certificates.')

        for certificate in additional_certificates:
            if not isinstance(certificate, x509.Certificate):
                raise TypeError('additional_certificates contains at least one element that is not a x509.Certificate.')

        self._credential_private_key = credential_private_key
        self._credential_certificate = credential_certificate
        self._additional_certificates = additional_certificates

    @classmethod
    def from_crypto(
        cls,
        credential_private_key: PrivateKey,
        credential_certificate: x509.Certificate,
        additional_certificates: list[x509.Certificate],
    ) -> CredentialSerializer:
        """Inits the CredentialSerializer class from a PrivateKey, x509.Certificate and additional x509.Certificates.

        Args:
            credential_private_key: The private key corresponding to the credential.
            credential_certificate: The credential certificate containing the public key that matches the private key.
            additional_certificates: A list of x509.Certificates. Usually the corresponding certificate chain.

        Returns:
            CredentialSerializer: CredentialSerializer instance.

        Raises:
            TypeError:
                If credential_private_key is not an instance of PrivateKey.
                if credential_certificate is not an instance of x509.Certificate.
                If additional_certificates is not None or and instance of list[x509.Certificate].
        """
        return cls(credential_private_key, credential_certificate, additional_certificates)

    @classmethod
    def from_crypto_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CredentialSerializer:
        """Inits the CredentialSerializer class from a pkcs12.PKCS12 instance.

        Args:
            p12: A pkcs12.PKCS12 instance containing the credential.

        Returns:
            CredentialSerializer: CredentialSerializer instance.

        Raises:
            ValueError: If the pkcs12.PKCS12 instance does not contain the credential private key and certificate.
        """
        return cls(p12.key, p12.cert.certificate, [certificate.certificate for certificate in p12.additional_certs])

    @classmethod
    def from_bytes(cls, credential_data: bytes, password: None | bytes = None) -> CredentialSerializer:
        """Inits the CredentialSerializer class from a bytes object.

        Args:
            credential_data: Bytes that contain PKCS#12 object.
            password: Password as bytes if the content is encrypted, None otherwise.

        Returns:
            CredentialSerializer: CredentialSerializer instance.

        Raises:
            ValueError: If loading the PKCS#12 object failed.
        """
        try:
            return cls(**cls._load_pkcs12(credential_data, password))
        except ValueError:
            raise ValueError('Failed to load credential. May be an incorrect password or malformed data.')

    def as_pkcs12(self, password: None | bytes, friendly_name: bytes = b'') -> bytes:
        """Gets the credential as bytes in PKCS#12 format.

        Args:
            password: Password if the credential shall be encrypted, None otherwise.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            bytes: Bytes that contains the credential in PKCS#12 format.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._credential_private_key,
            cert=self._credential_certificate,
            cas=self._additional_certificates,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def get_credential_private_key_serializer(self) -> PrivateKeySerializer:
        """Gets the PrivateKeySerializer instance of the associated credential private key.

        Returns:
            PrivateKeySerializer: PrivateKeySerializer instance of the associated credential private key.
        """
        return self._private_key_serializer_class(self._credential_private_key)

    def get_credential_certificate_serializer(self) -> CertificateSerializer:
        """Gets the CertificateSerializer instance of the associated credential certificate.

        Returns:
            CertificateSerializer: CertificateSerializer instance of the associated credential certificate.
        """
        return self._certificate_serializer_class(self._credential_certificate)

    def get_additional_certificate_serializer(self) -> CertificateCollectionSerializer:
        """Gets the CertificateCollectionSerializer instance of the associated additional certificates.

        Returns:
            CertificateCollectionSerializer:
                CertificateCollectionSerializer instance of the associated additional certificates.
        """
        return self._certificate_collection_serializer_class.from_crypto(self._additional_certificates)

    def get_certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        """Gets the CertificateCollectionSerializer instance of the associated additional certificates
        including the credential certificate.

        Returns:
            CertificateCollectionSerializer:
                CertificateCollectionSerializer instance of the associated additional certificates
                including the credential certificate.
        """
        certificates = [self._credential_certificate]
        certificates.extend(self._additional_certificates)
        return self._certificate_collection_serializer_class.from_crypto(certificates)

    @staticmethod
    def _get_encryption_algorithm(password: None | bytes):
        if password:
            return serialization.BestAvailableEncryption(password)
        return serialization.NoEncryption()

    @staticmethod
    def _load_pkcs12(
        p12_data: bytes, password: None | bytes = None
    ) -> (PrivateKey, x509.Certificate, list[x509.Certificate]):
        try:
            return pkcs12.load_key_and_certificates(p12_data, password)
        except Exception:   # noqa: BLE001
            raise ValueError
