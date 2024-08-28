from __future__ import annotations

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256


from pki.serializer import (
    PublicKeySerializer,
    PrivateKeySerializer,
    CertificateCollectionSerializer,
    CredentialSerializer, CertificateSerializer)



class CredentialExtractorError(ValidationError):
    """Base class for Errors raised by the CredentialExtractor class."""
    pass


class UnexpectedCredentialError(ValidationError):
    """Raised if an unexpected error occurred while trying to extract the credential."""

    def __init__(self, message: None | str = None) -> None:
        if message:
            super().__init__(message)
        else:
            super().__init__(message=_(
                'Unexpected error occurred. Please see the logs or contact the Trustpoint support.'))

class MissingIssuingCaCertificate(CredentialExtractorError):
    """Raised if the Issuing CA Certificate is missing."""

    def __init__(self) -> None:
        super().__init__(message=_(
            'No Issuing CA Certificate found matching the uploaded private key. '
            'Please check your credential file(s).'))


class IncompleteCertificateChainError(CredentialExtractorError):
    """Raised if the corresponding certificate chain is incomplete."""

    def __init__(self) -> None:
        super().__init__(message=_(
            'Failed to construct full certificate chain from the uploaded file(s). '
            'Please make sure that the full certificate chain is included. '
            'The Issuing CA certificate up to the Root CA certificate is required.'))


class MultipleIssuingCaCertificatesFoundError(CredentialExtractorError):
    """Raised if multiple Issuing CA certificates were found."""

    def __init__(self) -> None:
        super().__init__(message=_(
            'The uploaded file(s) contain multiple possible Issuing CA certificates.'
            'Please make sure that only one single valid chain is included.'))


class MultipleCertificateChainsFoundError(CredentialExtractorError):
    """Raised if multiple certificate chains were found."""

    def __init__(self) -> None:
        super().__init__(message=_(
            'The uploaded file(s) contain multiple certificate chains (cross-signed certificates). '
            'Please make sure to only include a single certificate chain for the Issuing CA.'))


class CertificateChainContainsCycleError(CredentialExtractorError):
    """Raised if the corresponding certificate chain contains a cycle (graph)."""

    def __init__(self) -> None:
        super().__init__(message=_(
            'The uploaded file(s) contain a inconsistent certificate chain which contains a cycle (graph). '
            '(E.g. Certificate A singed B, B signed C and C singed A.)'
        ))


class Sha256Fingerprint:
    """Class that provides simple class methods to get the SHA256 fingerprint of certificates in different formats."""

    @classmethod
    def get_fingerprint(cls, certificate: x509.Certificate) -> bytes:
        return certificate.fingerprint(SHA256())

    @classmethod
    def get_fingerprint_hex_str(cls, certificate: x509.Certificate) -> str:
        return cls.get_fingerprint(certificate).hex().upper()


class CredentialExtractor:
    """Class that tries to extras a valid credential given a private key and a collection of certificates.

    Required are a single private key matching certificate and the full certificate chain up to a self-signed
    Root CA certificate.
    """

    _public_key_serializer: PublicKeySerializer
    _certificate_collection: CertificateCollectionSerializer
    _issuing_ca_certificate: CertificateSerializer

    _private_key_serializer: PrivateKeySerializer
    _certificate_chain: None | CertificateCollectionSerializer
    _certificate_credential: None | CredentialSerializer = None

    def __init__(
            self,
            private_key_serializer: PrivateKeySerializer,
            certificate_collection_serializer: CertificateCollectionSerializer) -> None:
        """Inits the CredentialExtractor class.

        Args:
            private_key_serializer: The private key of the credential.
            certificate_collection_serializer: A collection of certificates.
        """
        self._private_key_serializer = private_key_serializer
        self._public_key_serializer = private_key_serializer.public_key_serializer
        self._certificate_collection = certificate_collection_serializer

    def extract_credential(self) -> CredentialSerializer:
        """Tries to extract the credential from the given private key and collection of certificates.

        Returns:
            CredentialSerializer:
                The CredentialSerializer containing the private key, credential certificate matching the private key
                and a full certificate chain up to and including a self-signed Root CA certificate.

        Raises:
            UnexpectedCredentialError: If an unexpected error occurred while trying to extract the credential.
            MissingIssuingCaCertificate: If the Issuing CA certificate is missing.
            IncompleteCertificateChainError: If the corresponding certificate chain is incomplete.
            MultipleIssuingCaCertificatesFoundError: If multiple Issuing CA certificates were found.
            MultipleCertificateChainsFoundError: If multiple certificate chains were found.
            CertificateChainContainsCycleError: If the corresponding certificate chain contains a cycle (graph).
        """
        try:
            if self._certificate_credential is not None:
                return self._certificate_credential

            self._remove_duplicates_from_certificate_collection()
            self._get_issuing_ca_certificate()
            self._get_certificate_chain()

            self._certificate_credential = CredentialSerializer(
                credential=(
                    self._private_key_serializer.as_crypto(),
                    self._issuing_ca_certificate.as_crypto(),
                    self._certificate_chain.as_crypto()
                )
            )
        except Exception as exception:
            if isinstance(exception, CredentialExtractorError):
                raise exception
            else:
                error_msg = str(exception)
                if len(error_msg) >= 4:
                    error_msg = error_msg[2:-2]
                raise UnexpectedCredentialError(error_msg)

        return self._certificate_credential


    def _remove_duplicates_from_certificate_collection(self) -> None:
        der_certificates = self._certificate_collection.as_der_list()
        disjoint_list = list(set(der_certificates))
        self._certificate_collection = CertificateCollectionSerializer(disjoint_list)

    def _get_issuing_ca_certificate(self) -> None:
        public_key_der_from_private_key = self._public_key_serializer.as_der()
        issuing_ca_certs = [
            cert for cert in self._certificate_collection.as_certificate_serializer_list()
            if public_key_der_from_private_key == cert.public_key_serializer.as_der()]

        if len(issuing_ca_certs) == 0:
            raise MissingIssuingCaCertificate()
        if len(issuing_ca_certs) > 1:
            raise MultipleIssuingCaCertificatesFoundError

        self._issuing_ca_certificate = issuing_ca_certs[0]

    def _get_certificate_chain(self) -> None:
        current_cert = self._issuing_ca_certificate.as_crypto()
        certs = self._certificate_collection.as_crypto_list()
        cert_chain = []

        # extra flag, if this should be allowed
        if self._is_self_signed(current_cert):
            self._certificate_chain = None

        processed_certs = [Sha256Fingerprint.get_fingerprint(current_cert)]

        while not self._is_self_signed(current_cert):
            issuer = self._get_issuer_certificate(current_cert, self._certificate_collection.as_crypto_list())
            certs.remove(issuer)
            fingerprint = Sha256Fingerprint.get_fingerprint(issuer)
            if fingerprint in processed_certs:
                raise CertificateChainContainsCycleError
            processed_certs.append(fingerprint)
            cert_chain.append(issuer)
            current_cert = issuer

        cert_chain.reverse()

        self._certificate_chain = CertificateCollectionSerializer(cert_chain)

    @staticmethod
    def _is_self_signed(certificate: x509.Certificate) -> bool:
        if certificate.subject == certificate.issuer:
            try:
                certificate.verify_directly_issued_by(certificate)
                return True
            except (ValueError, TypeError, InvalidSignature):
                return False

    @staticmethod
    def _get_issuer_certificate(
            certificate: x509.Certificate,
            issuer_candidates: list[x509.Certificate]) -> x509.Certificate:

        issuers = []

        for issuer_candidate in issuer_candidates:
            if certificate.issuer != issuer_candidate.subject:
                continue
            try:
                certificate.verify_directly_issued_by(issuer_candidate)
                issuers.append(issuer_candidate)
            except (ValueError, TypeError, InvalidSignature):
                pass

        if len(issuers) == 0:
            raise IncompleteCertificateChainError
        if len(issuers) > 1:
            raise MultipleCertificateChainsFoundError
        return issuers[0]

