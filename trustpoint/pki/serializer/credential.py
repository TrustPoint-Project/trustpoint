"""The credential module provides Serializer classes for X.509 Credential serialization."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


from . import Serializer, PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer
from . import PrivateKey


class CredentialSerializer(Serializer):
    """The CredentialSerializer class provides methods for serializing and loading X.509 Credentials.

    These Credentials consist of one private key and the corresponding certificate. Further certificates, like
    the corresponding certificate chain may also be included.

    Warnings:
        The CredentialSerializer class does not evaluate or validate any contents of the credential,
        i.e. neither the certificate chain nor if the private key matches the certificate is validated.
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
