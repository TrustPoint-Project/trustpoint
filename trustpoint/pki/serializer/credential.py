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

    _credential_private_key: PrivateKeySerializer
    _credential_certificate: CertificateSerializer
    _additional_certificates: None | CertificateCollectionSerializer = None

    def __init__(
            self,
            credential: None | bytes | pkcs12.PKCS12KeyAndCertificates | CredentialSerializer,
            password: None | bytes = None,
            credential_private_key: None | bytes | str | PrivateKey | PrivateKeySerializer = None,
            credential_certificate: None | bytes | str | x509.Certificate | CertificateSerializer = None,
            additional_certificates: None | bytes | str | \
                                     list[bytes | str | x509.Certificate | CertificateSerializer] | \
                                     CertificateCollectionSerializer = None
    ) -> None:
        """Inits the CredentialSerializer class.

        Either a credential or both credential_private_key and credential_certificate must be provided.

        Args:
            credential:
                A PKCS#12 credential as bytes or pkcs12.PKCS12KeyAndCertificates, or a CredentialSerializer instance.
            password: The password for either the credential or the credential_private_key, if any.
            credential_private_key: The credential private key.
            credential_certificate: The credential certificate matching the private key.
            additional_certificates: Additional certificates, typically the certificate chain.

        Raises:
            TypeError: If an invalid argument type was provided for any of the parameters.
            ValueError: If the credential failed to deserialize.
        """

        if password == b'':
            password = None

        if credential is not None:
            if isinstance(credential, bytes):
                cred_priv_key, cred_cert, add_certs = self._from_bytes_pkcs12(credential, password)
                self._credential_private_key = cred_priv_key
                self._credential_certificate = cred_cert
                self._additional_certificates = add_certs
            elif isinstance(credential, pkcs12.PKCS12KeyAndCertificates):
                cred_priv_key, cred_cert, add_certs = self._from_crypto_pkcs12(credential)
                self._credential_private_key = cred_priv_key
                self._credential_certificate = cred_cert
                self._additional_certificates = add_certs
            elif isinstance(credential, CredentialSerializer):
                self._credential_private_key = credential.credential_private_key
                self._credential_certificate = credential.credential_certificate
                self._additional_certificates = credential.additional_certificates
            else:
                raise TypeError(
                    'credential must be of type bytes, pkcs12.PKCS12KeyAndCertificates or CredentialSerializer, '
                    f'but got {type(credential)}.')
            return

        if credential_private_key is not None and credential_certificate is not None:
            self._credential_private_key = PrivateKeySerializer(credential_private_key)
            self._credential_certificate = CertificateSerializer(credential_certificate)

            if additional_certificates is not None:
                additional_certificates = CertificateCollectionSerializer(additional_certificates)
            self._additional_certificates = additional_certificates
        else:
            raise TypeError(
                'To instantiate a CredentialSerializer, either credential or '
                'credential_private_key and credential_certificate must be provided.')


    @staticmethod
    def _from_crypto_pkcs12(p12: pkcs12.PKCS12KeyAndCertificates
                            ) -> tuple[PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer]:
        additional_certificates = [
            CertificateSerializer(certificate.certificate) for certificate in p12.additional_certs]
        return (
            PrivateKeySerializer(p12.key),
            CertificateSerializer(p12.cert.certificate),
            CertificateCollectionSerializer(additional_certificates))

    def _from_bytes_pkcs12(self, credential_data: bytes, password: None | bytes = None
                          ) -> tuple[PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer]:
        try:
            return self._from_crypto_pkcs12(pkcs12.load_pkcs12(credential_data, password))
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
            key=self._credential_private_key.as_crypto(),
            cert=self._credential_certificate.as_crypto(),
            cas=self._additional_certificates.as_crypto(),
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def __len__(self) -> int:
        """Returns the number of certificates contained in this credential."""
        if self._additional_certificates is None:
            return 0
        else:
            return len(self._additional_certificates) + 1

    @property
    def credential_private_key(self) -> PrivateKeySerializer:
        """Returns the credential private key as PrivateKeySerializer instance."""
        return self._credential_private_key

    @credential_private_key.setter
    def credential_private_key(self, credential_private_key: PrivateKeySerializer) -> None:
        """Sets the credential private key."""
        self._credential_private_key = credential_private_key

    @property
    def credential_certificate(self) -> CertificateSerializer:
        """Returns the credential certificate as CertificateSerializer instance."""
        return self._credential_certificate

    @credential_certificate.setter
    def credential_certificate(self, credential_certificate: CertificateSerializer) -> None:
        """Sets the credential certificate."""
        self._credential_certificate = credential_certificate

    @property
    def additional_certificates(self) -> CertificateCollectionSerializer:
        """Returns the additional certificates as CertificateCollectionSerializer instance."""
        return self._additional_certificates

    @additional_certificates.setter
    def additional_certificates(
            self,
            additional_certificates: CertificateCollectionSerializer) -> None:
        """Sets the additional certificates."""
        self._additional_certificates = additional_certificates

    @property
    def all_certificates(self) -> CertificateCollectionSerializer:
        """Returns both the credential and additional certificates as CertificateCollectionSerializer instance."""
        if self._additional_certificates is None:
            return CertificateCollectionSerializer([self._credential_certificate])
        else:
            new_collection = CertificateCollectionSerializer(self._additional_certificates)
            new_collection.append(self._credential_certificate)
            return new_collection

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
