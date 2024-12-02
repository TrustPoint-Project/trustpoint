from __future__ import annotations

from cryptography.exceptions import InvalidSignature

from core.serializer import CertificateSerializer, CertificateCollectionSerializer, CredentialSerializer
from cryptography import x509
from trustpoint.views.base import LoggerMixin


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography import x509
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    PrivateKey = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]
    PublicKey = Union[ec.EllipticCurvePublicKey, rsa.RSAPublicKey]


class CertificateChainExtractor(LoggerMixin):

    _certificate: x509.Certificate

    # The certificate collection passed into the constructor.
    _initial_certificate_collection: list[x509.Certificate]

    # The certificate collection without any duplicates.
    _certificate_collection: list[x509.Certificate]

    # The extracted certificate chain, excl. the certificate for which the certificate chain was extracted
    _certificate_chain: list[x509.Certificate]

    @LoggerMixin.log_exceptions
    def __init__(
            self,
            certificate_serializer: CertificateSerializer,
            certificate_collection_serializer: CertificateCollectionSerializer
    ) -> None:
        self._certificate = certificate_serializer.as_crypto()
        self._initial_certificate_collection = certificate_collection_serializer.as_crypto()

        if self._initial_certificate_collection:
            self._certificate_collection = list(dict.fromkeys(self._initial_certificate_collection))
        else:
            self._certificate_collection = []

        self._extract_certificate_chain()

    @staticmethod
    @LoggerMixin.log_exceptions
    def _verify_directly_issued_by(certificate: x509.Certificate, potential_issuer: x509.Certificate) -> bool:
        try:
            certificate.verify_directly_issued_by(potential_issuer)
            return True
        except (ValueError, TypeError, InvalidSignature):
            return False

    @LoggerMixin.log_exceptions
    def _extract_certificate_chain(self) -> None:
        if self.certificate_collection_size == 0:
            self._certificate_chain = []
            return

        certificate_chain = []
        current_certificate = self._certificate

        while True:
            issuers = [
                certificate for certificate in self._certificate_collection
                if self._verify_directly_issued_by(certificate=current_certificate, potential_issuer=certificate)
            ]

            if len(issuers) == 0:
                break
            elif len(issuers) == 1:
                certificate_chain.append(issuers[0])
                if current_certificate == issuers[0]:
                    break
                current_certificate = issuers[0]
                continue
            else:
                raise ValueError('Found multiple valid certificate chains.')

        self._certificate_chain = certificate_chain

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def certificate_serializer(self) -> CertificateSerializer:
        return CertificateSerializer(self.certificate)

    @property
    def initial_certificate_collection(self) -> list[x509.Certificate]:
        return self._initial_certificate_collection

    @property
    def initial_certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(self.initial_certificate_collection)

    @property
    def initial_certificate_collection_size(self) -> int:
        return len(self.initial_certificate_collection)

    @property
    def certificate_collection(self) -> list[x509.Certificate]:
        return self._certificate_collection

    @property
    def certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(self.certificate_collection)

    @property
    def certificate_collection_size(self) -> int:
        return len(self.certificate_collection)

    @property
    def certificate_chain(self) -> list[x509.Certificate]:
        return self._certificate_chain

    @property
    def certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(self.certificate_chain)

    @property
    def certificate_chain_size(self) -> int:
        return len(self.certificate_chain)

    @property
    def certificate_chain_including_certificate(self) -> list[x509.Certificate]:
        return [self._certificate] + self._certificate_chain

    @property
    def certificate_chain_including_certificate_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(self.certificate_chain_including_certificate)



class CredentialNormalizer(LoggerMixin):

    _normalized_credential: CredentialSerializer

    @LoggerMixin.log_exceptions
    def __init__(self, credential_serializer: CredentialSerializer) -> None:
        if not self.verify_matching_private_key_and_certificates(
                private_key=credential_serializer.credential_private_key.as_crypto(),
                certificate=credential_serializer.credential_certificate.as_crypto()):
            raise ValueError('The private key does not match the certificate. This is not a valid credential.')
        normalized_additional_certificates = CertificateChainExtractor(
            certificate_serializer=credential_serializer.credential_certificate,
            certificate_collection_serializer=credential_serializer.additional_certificates
        )

        self._normalized_credential = CredentialSerializer(
            (
                credential_serializer.credential_private_key,
                credential_serializer.credential_certificate,
                normalized_additional_certificates
            )
        )

    @property
    def normalized_credential(self) -> CredentialSerializer:
        return self._normalized_credential

    @staticmethod
    @LoggerMixin.log_exceptions
    def verify_matching_private_key_and_certificates(private_key: PrivateKey, certificate: x509.Certificate) -> bool:
        if private_key.public_key() == certificate.public_key():
            return True
        return False
