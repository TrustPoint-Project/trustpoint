"""The key module provides Serializer classes for cryptographic key serialization."""


from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs12

from typing import get_args

from . import Serializer
from . import PublicKey, PrivateKey


class PublicKeySerializer(Serializer):
    """The PublicKeySerializer class provides methods for serializing and loading a public key.

    Warnings:
        The PublicKeySerializer class does not evaluate or validate any contents of the public key.
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
