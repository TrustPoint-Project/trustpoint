"""The key module provides Serializer classes for cryptographic key serialization."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs12

from . import PrivateKey, PublicKey, Serializer


class PublicKeySerializer(Serializer):
    """The PublicKeySerializer class provides methods for serializing and loading a public key.

    Warnings:
        The PublicKeySerializer class does not evaluate or validate any contents of the public key.
    """

    _public_key: PublicKey

    def __init__(self, public_key: bytes | str | PublicKey | PublicKeySerializer) -> None:
        """Inits the PublicKeySerializer class.

        Args:
            public_key: The public key to serialize (rsa, ec, ed448 or ed25519).

        Raises:
            TypeError: If the public key is not of type bytes, str, PublicKey or PublicKeySerializer.
            ValueError: If the public key failed to deserialize.
        """
        if isinstance(public_key, bytes):
            self._public_key = self._from_bytes(public_key)
        elif isinstance(public_key, str):
            self._public_key = self._from_string(public_key)
        elif isinstance(public_key, PublicKey):
            self._public_key = public_key
        elif isinstance(public_key, PublicKeySerializer):
            self._public_key = public_key.as_crypto()
        else:
            err_msg = (
                'public_key must be of type bytes, str, PublicKey or PublicKeySerializer, '
                f'but got {type(public_key)}.'
            )
            raise TypeError(err_msg)

    def _from_bytes(self, public_key_data: bytes) -> PublicKey:
        try:
            return self._load_pem_public_key(public_key_data)
        except ValueError:
            pass

        try:
            return self._load_der_public_key(public_key_data)
        except ValueError:
            pass

        err_msg = 'Failed to load public key. May be malformed or not in a DER or PEM format.'
        raise ValueError(err_msg)

    def _from_string(self, public_key_data: str) -> PublicKey:
        return self._from_bytes(public_key_data.encode())

    def serialize(self) -> bytes:
        """Default serialization method that gets the associated public key as bytes in PEM format.

        Returns:
            bytes: Bytes that contains the public key in PEM format.
        """
        return self.as_pem()

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
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_der_public_key(public_key_data: bytes) -> PublicKey:
        try:
            return serialization.load_der_public_key(public_key_data)
        except Exception as exception:
            raise ValueError from exception


class PrivateKeySerializer(Serializer):
    """The PrivateKeySerializer class provides methods for serializing and loading a private key.

    Warnings:
        The PrivateKeySerializer class does not evaluate or validate any contents of the private key.
    """

    _private_key: PrivateKey

    def __init__(
        self, private_key: bytes | str | PrivateKey | PrivateKeySerializer, password: None | bytes = None
    ) -> None:
        """Inits the PrivateKeySerializer class.

        Args:
            private_key: The private key to serialize (rsa, ec, ed448 or ed25519).
            password: The password for the private key, if any.

        Raises:
            TypeError: If the private key is not of type bytes, str, PrivateKey or PrivateKeySerializer.
            ValueError: If the private key failed to deserialize.
        """
        if password == b'':
            password = None

        if isinstance(private_key, bytes):
            self._private_key = self._from_bytes(private_key, password)
        elif isinstance(private_key, str):
            self._private_key = self._from_string(private_key, password)
        elif isinstance(private_key, PrivateKey):
            self._private_key = private_key
        elif isinstance(private_key, PrivateKeySerializer):
            self._private_key = private_key.as_crypto()
        else:
            err_msg = (
                'private_key must be of type bytes, str, PrivateKey or PrivateKeySerializer, '
                f'but got {type(private_key)}.'
            )
            raise TypeError(err_msg)

    def _from_bytes(self, private_key: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return self._load_pem_private_key(private_key, password)
        except ValueError:
            pass

        try:
            return self._load_der_private_key(private_key, password)
        except ValueError:
            pass

        try:
            return self._load_pkcs12_private_key(private_key, password)
        except ValueError:
            pass

        err_msg = 'Failed to load private key. May be an incorrect password, malformed data or an unsupported format.'
        raise ValueError(err_msg)

    def _from_string(self, private_key: str, password: None | bytes = None) -> PrivateKey:
        return self._from_bytes(private_key.encode(), password)

    def serialize(self, password: None | bytes = None) -> bytes:
        """Default serialization method that gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self.as_pkcs8_pem(password=password)

    def as_pkcs1_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs1_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 PEM format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 PEM format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs12(self, password: None | bytes = None, friendly_name: bytes = b'') -> bytes:
        """Gets the associated private key as bytes in PKCS#12 format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.
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

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Gets the PublicKeySerializer instance of the associated private key.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance of the associated private key.
        """
        return PublicKeySerializer(self._private_key.public_key())

    @staticmethod
    def _get_encryption_algorithm(password: None | bytes = None) -> serialization.KeySerializationEncryption:
        if password:
            return serialization.BestAvailableEncryption(password)
        return serialization.NoEncryption()

    @staticmethod
    def _load_pem_private_key(private_key: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return serialization.load_pem_private_key(private_key, password)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_der_private_key(private_key: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return serialization.load_der_private_key(private_key, password)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_pkcs12_private_key(p12_data: bytes, password: None | bytes = None) -> PrivateKey:
        try:
            return pkcs12.load_pkcs12(p12_data, password).key
        except Exception as exception:
            raise ValueError from exception
