"""X.509 utility classes and methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

if TYPE_CHECKING:
    from typing import Union

    from cryptography import x509

    PrivateKey = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
    PublicKey = Union[ec.EllipticCurvePublicKey, rsa.RSAPublicKey]
    from pki.models.credential import CredentialModel
    from pki.models.domain import DomainModel


class CertificateChainExtractor:
    """Extracts the certificate chain corresponding to a given certificate form a set of certificates."""

    _certificate: x509.Certificate

    # The certificate collection passed into the constructor.
    _initial_certificate_collection: list[x509.Certificate]

    # The certificate collection without any duplicates.
    _certificate_collection: list[x509.Certificate]

    # The extracted certificate chain, excl. the certificate for which the certificate chain was extracted
    _certificate_chain: list[x509.Certificate]

    def __init__(
        self,
        certificate_serializer: CertificateSerializer,
        certificate_collection_serializer: CertificateCollectionSerializer,
    ) -> None:
        """Initializes a CertificateChainExtractor instance.

        Args:
            certificate_serializer: Contains the certificate for which the certificate chain should be extracted.
            certificate_collection_serializer: The set of certificates to extract the certificate chain from.
        """
        self._certificate = certificate_serializer.as_crypto()
        self._initial_certificate_collection = certificate_collection_serializer.as_crypto()

        if self._initial_certificate_collection:
            self._certificate_collection = list(dict.fromkeys(self._initial_certificate_collection))
        else:
            self._certificate_collection = []

        self._extract_certificate_chain()

    @staticmethod
    def _verify_directly_issued_by(certificate: x509.Certificate, potential_issuer: x509.Certificate) -> bool:
        try:
            certificate.verify_directly_issued_by(potential_issuer)
        except (ValueError, TypeError, InvalidSignature):
            return False
        else:
            return True

    def _extract_certificate_chain(self) -> None:
        if self.certificate_collection_size == 0:
            self._certificate_chain = []
            return

        certificate_chain = []
        current_certificate = self._certificate

        while True:
            issuers = [
                certificate
                for certificate in self._certificate_collection
                if self._verify_directly_issued_by(certificate=current_certificate, potential_issuer=certificate)
            ]

            if len(issuers) == 0:
                break
            if len(issuers) == 1:
                if current_certificate == issuers[0]:
                    break
                certificate_chain.append(issuers[0])
                current_certificate = issuers[0]
                continue
            err_msg = 'Found multiple valid certificate chains.'
            raise ValueError(err_msg)

        self._certificate_chain = certificate_chain

    @property
    def certificate(self) -> x509.Certificate:
        """Gets the certificate."""
        return self._certificate

    @property
    def certificate_serializer(self) -> CertificateSerializer:
        """Gets the certificate."""
        return CertificateSerializer(self.certificate)

    @property
    def initial_certificate_collection(self) -> list[x509.Certificate]:
        """Gets the set of certificates."""
        return self._initial_certificate_collection

    @property
    def initial_certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        """Gets the set of certificates."""
        return CertificateCollectionSerializer(self.initial_certificate_collection)

    @property
    def initial_certificate_collection_size(self) -> int:
        """Gets the size of the set of certificates"""
        return len(self.initial_certificate_collection)

    @property
    def certificate_collection(self) -> list[x509.Certificate]:
        """Gets the set of certificates without any duplicates."""
        return self._certificate_collection

    @property
    def certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        """Gets the set of certificates without any duplicates."""
        return CertificateCollectionSerializer(self.certificate_collection)

    @property
    def certificate_collection_size(self) -> int:
        """Gets the size of the set of certificates without any duplicates."""
        return len(self.certificate_collection)

    @property
    def certificate_chain(self) -> list[x509.Certificate]:
        """Gets the extracted certificate chain."""
        return self._certificate_chain

    @property
    def certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        """Gets the extracted certificate chain."""
        return CertificateCollectionSerializer(self.certificate_chain)

    @property
    def certificate_chain_size(self) -> int:
        """Gets the size of the set of the extracted certificate chain without any duplicates."""
        return len(self.certificate_chain)

    @property
    def certificate_chain_including_certificate(self) -> list[x509.Certificate]:
        """Gets the extracted certificate chain including the certificate corresponding to the chain."""
        return [self._certificate, *self._certificate_chain]

    @property
    def certificate_chain_including_certificate_serializer(self) -> CertificateCollectionSerializer:
        """Gets the extracted certificate chain including the certificate corresponding to the chain."""
        return CertificateCollectionSerializer(self.certificate_chain_including_certificate)


class CredentialNormalizer:
    """Normalizes a given credential, e.g. removes all additional certificates not part of the chain."""

    _normalized_credential: CredentialSerializer

    def __init__(self, credential_serializer: CredentialSerializer) -> None:
        """Initializes a CredentialNormalizer instance with a given credential serializer.

        Args:
            credential_serializer: The credential to normalize.
        """
        if not self.verify_matching_private_key_and_certificates(
            private_key=credential_serializer.credential_private_key.as_crypto(),
            certificate=credential_serializer.credential_certificate.as_crypto(),
        ):
            err_msg = 'The private key does not match the certificate. This is not a valid credential.'
            raise ValueError(err_msg)
        normalized_additional_certificates = CertificateChainExtractor(
            certificate_serializer=credential_serializer.credential_certificate,
            certificate_collection_serializer=credential_serializer.additional_certificates,
        )

        self._normalized_credential = CredentialSerializer(
            (
                credential_serializer.credential_private_key,
                credential_serializer.credential_certificate,
                normalized_additional_certificates.certificate_chain,
            )
        )

    @property
    def normalized_credential(self) -> CredentialSerializer:
        """Gets the normalized credential."""
        return self._normalized_credential

    @staticmethod
    def verify_matching_private_key_and_certificates(private_key: PrivateKey, certificate: x509.Certificate) -> bool:
        """Verifies if the private key matches the certificate.

        Args:
            private_key: The private key to check against the certificate.
            certificate: The certificate to check against the private key.

        Returns:
            True if the private key matches the certificate, False otherwise.
        """
        return private_key.public_key() == certificate.public_key()


class CryptographyUtils:
    """Utilities methods for cryptography corresponding to Trustpoint models.

    TODO(AlexHx8472): Move this out of the core.
    """

    @staticmethod
    def generate_private_key(domain: DomainModel) -> PrivateKeySerializer:
        """Generates a key pair of the type corresponding to the domain model.

        Args:
            domain: The domain to consider.

        Returns:
            The generated private key / key pair.
        """
        issuing_ca_private_key = domain.issuing_ca.credential.get_private_key()
        if isinstance(issuing_ca_private_key, rsa.RSAPrivateKey):
            key_size = issuing_ca_private_key.key_size
            return PrivateKeySerializer(rsa.generate_private_key(key_size=key_size, public_exponent=65537))
        if isinstance(issuing_ca_private_key, ec.EllipticCurvePrivateKey):
            curve = issuing_ca_private_key.curve
            return PrivateKeySerializer(ec.generate_private_key(curve=curve))
        err_msg = 'Cannot build the domain credential, unknown key type found.'
        raise ValueError(err_msg)

    @classmethod
    def get_hash_algorithm_from_domain(cls, domain: DomainModel) -> hashes.SHA256 | hashes.SHA384:
        """Gets the hash algorithm for a given domain.

        Args:
            domain: The domain to consider.

        Returns:
            The hash algorithm as cryptography object.
        """
        return cls.get_hash_algorithm_from_credential(domain.issuing_ca.credential)

    @staticmethod
    def get_hash_algorithm_from_credential(credential: CredentialModel) -> hashes.SHA256 | hashes.SHA384:
        """Gets the hash algorithm for a given credential model.

        Args:
            credential: The credential to consider.

        Returns:
            The hash algorithm as cryptography object.
        """
        hash_algorithm = credential.get_certificate().signature_hash_algorithm
        if isinstance(hash_algorithm, hashes.SHA256):
            return hashes.SHA256()
        if isinstance(hash_algorithm, hashes.SHA384):
            return hashes.SHA384()
        err_msg = 'Cannot build the domain credential, unknown hash algorithm found.'
        raise ValueError(err_msg)
