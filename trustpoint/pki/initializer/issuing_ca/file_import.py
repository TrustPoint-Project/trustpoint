from __future__ import annotations

import abc
import logging

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256

from pki.models import CertificateModel, IssuingCaModel, CertificateChainOrderModel

from pki.serializer import (
    PublicKeySerializer,
    PrivateKeySerializer,
    CertificateSerializer,
    CertificateCollectionSerializer,
    CredentialSerializer
)

from . import IssuingCaInitializer
from . import IssuingCaInitializerError

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]

log = logging.getLogger('tp.pki.initializer')

# TODO: USE SERIALIZERS ONLY, NO x509 directly


class FileImportLocalIssuingCaInitializerError(IssuingCaInitializerError):
    pass


class InternalServerError(FileImportLocalIssuingCaInitializerError):
    """Raised if an unexpected error occurred.

     E.g. is raised, if .initialize() is not called before .save()
     """

    def __init__(self) -> None:
        super().__init__(message=_(
            f'An unexpected internal server error occurred.'
            f'Please contact the Trust-Point support '))


class TooManyCertificatesError(FileImportLocalIssuingCaInitializerError):

    def __init__(self, cert_count: int, limit: int) -> None:
        super().__init__(message=_(
            f'The uploaded file(s) contain more than {cert_count} certificates. '
            f'Refusing to process more than {limit} certificates.'))


class MissingIssuingCaCertificate(FileImportLocalIssuingCaInitializerError):
    def __init__(self) -> None:
        super().__init__(message=_(
            'No Issuing CA Certificate found matching the uploaded private key. '
            'Please check your credential file(s).'))


class IncompleteCertificateChainError(FileImportLocalIssuingCaInitializerError):

    def __init__(self) -> None:
        super().__init__(message=_(
            'Failed to construct full certificate chain from the uploaded file(s). '
            'Please make sure that the full certificate chain is included. '
            'The Issuing CA certificate up to the Root CA certificate is required.'))


class MultipleCertificateChainsFoundError(FileImportLocalIssuingCaInitializerError):

    def __init__(self) -> None:
        super().__init__(message=_(
            'The uploaded file(s) contain multiple certificate chains (cross-signed certificates). '
            'Please make sure to only include a single certificate chain for the Issuing CA.'))


class CertificateChainContainsCycleError(FileImportLocalIssuingCaInitializerError):

    def __init__(self) -> None:
        super().__init__(message=_(
            'The uploaded file(s) contain a inconsistent certificate chain which contains a cycle. '
            '(E.g. Certificate A singed B, B signed C and C singed A.)'
        ))


class IssuingCaAlreadyExistsError(FileImportLocalIssuingCaInitializerError):

    def __init__(self, name: str) -> None:
        super().__init__(message=_(f'Issuing CA already exists with unique name: {name}.'))


class FileImportLocalIssuingCaInitializer(IssuingCaInitializer, abc.ABC):

    _CERTIFICATE_UPLOAD_FILE_LIMIT: int = 100

    _is_initialized: bool = False

    _unique_name: str
    _password: None | bytes
    _credential_serializer: CredentialSerializer

    _cert_model_class: type[CertificateModel] = CertificateModel
    _issuing_ca_model_class: type[IssuingCaModel] = IssuingCaModel
    _cert_chain_order_model_class: type[CertificateChainOrderModel] = CertificateChainOrderModel

    _public_key_serializer_class: type[PublicKeySerializer] = PublicKeySerializer
    _private_key_serializer_class: type[PrivateKeySerializer] = PrivateKeySerializer
    _certificate_serializer_class: type[CertificateSerializer] = CertificateSerializer
    _certificate_collection_serializer_class: type[CertificateCollectionSerializer] = CertificateCollectionSerializer
    _credential_serializer_class: type[CredentialSerializer] = CredentialSerializer


    @abc.abstractmethod
    def _construct_credential_serializer(self) -> None:
        pass

    @property
    def password(self) -> None | bytes:
        return self._password

    @password.setter
    def password(self, password: None | bytes) -> None:
        if password == b'':
            password = None
        self._password = password

    def _check_certificate_upload_file_limit(self) -> None:
        cert_count = self._credential_serializer.get_count_of_certificates() + 1
        if cert_count > self._CERTIFICATE_UPLOAD_FILE_LIMIT:
            raise TooManyCertificatesError(
                cert_count=cert_count,
                limit=self._CERTIFICATE_UPLOAD_FILE_LIMIT
            )

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

    @staticmethod
    def _get_fingerprint(certificate: x509.Certificate) -> bytes:
        return certificate.fingerprint(SHA256())

    def initialize(self) -> None:
        self._construct_credential_serializer()
        self._check_certificate_upload_file_limit()
        self._normalize_credential()
        # self._validate_credential()


    def _normalize_credential(self) -> None:

        private_key_serializer = self._credential_serializer.get_credential_private_key_serializer()
        public_key_bytes_from_private_key = private_key_serializer.get_public_key_serializer().as_der()

        certificates = [self._credential_serializer.get_credential_certificate_serializer().as_crypto()]
        certificates.extend(self._credential_serializer.get_certificate_collection_serializer().as_crypto())

        for certificate in certificates:
            if self._public_key_serializer_class(certificate.public_key()).as_der() == public_key_bytes_from_private_key:
                issuing_ca = certificate
                break
        else:
            raise MissingIssuingCaCertificate()

        cert_chain = self._get_certificate_chain(
            issuing_ca_cert=issuing_ca,
            additional_certificates=certificates
        )

        self._credential_serializer = self._credential_serializer_class(
            credential_private_key=private_key_serializer.as_crypto(),
            credential_certificate=issuing_ca,
            additional_certificates=cert_chain
        )


    # TODO: place this in global utils module
    def _get_certificate_chain(
            self,
            issuing_ca_cert: x509.Certificate,
            additional_certificates: list[x509.Certificate]) -> list[x509.Certificate]:

        current_cert = issuing_ca_cert
        certs = additional_certificates.copy()
        cert_chain = []

        # extra flag, if this should be allowed
        if self._is_self_signed(current_cert):
            return []

        processed_certs = [current_cert.fingerprint(SHA256())]

        while not self._is_self_signed(current_cert):

            issuer = self._get_issuer_certificate(current_cert, additional_certificates)
            certs.remove(issuer)
            fingerprint = self._get_fingerprint(issuer)
            if fingerprint in processed_certs:
                raise CertificateChainContainsCycleError
            processed_certs.append(fingerprint)
            cert_chain.append(issuer)
            current_cert = issuer

        cert_chain.reverse()
        return cert_chain

    @transaction.atomic
    def save(self):

        if not self._is_initialized:
            log.error(
                'Contents of an Initializer can\'t be stored to DB, if not yet initialized. '
                'Call .initialize() first.')

        issuing_ca_certificate = self._credential_serializer.get_credential_certificate_serializer().as_crypto()

        try:
            saved_certs = [self._cert_model_class.save_certificate(issuing_ca_certificate)]
        except ValueError:

            cert_model = CertificateModel.objects.get(
                sha256_fingerprint=self._get_fingerprint(issuing_ca_certificate).hex().upper())

            if hasattr(cert_model, 'issuing_ca_model'):
                raise IssuingCaAlreadyExistsError(name=cert_model.issuing_ca_model.unique_name)

            saved_certs = [cert_model]

        for certificate in self._credential_serializer.get_certificate_collection_serializer().as_crypto():
            saved_certs.append(self._cert_model_class.save_certificate(certificate, exist_ok=True))

        issuing_ca_model = self._issuing_ca_model_class(
            unique_name=self._unique_name,
            private_key_pem=self._credential_serializer.get_credential_private_key_serializer().as_pkcs1_pem(None)
        )

        issuing_ca_model.issuing_ca_certificate = saved_certs[0]
        issuing_ca_model.root_ca_certificate = saved_certs[-1]
        issuing_ca_model.save()

        for number, certificate in enumerate(saved_certs[1:-1]):
            cert_chain_order_model = self._cert_chain_order_model_class()
            cert_chain_order_model.order = number
            cert_chain_order_model.certificate = certificate
            cert_chain_order_model.issuing_ca = issuing_ca_model
            cert_chain_order_model.save()


class UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer(FileImportLocalIssuingCaInitializer):

    _p12: bytes

    def __init__(self, unique_name: str, p12: bytes, password: None | bytes = None) -> None:

        self.password = password

        self._unique_name = unique_name
        self._p12 = p12

    def _construct_credential_serializer(self) -> None:
        self._credential_serializer = self._credential_serializer_class.from_bytes_pkcs12(self._p12, self._password)


class UnprotectedFileImportLocalIssuingCaFromSeparateFilesInitializer(FileImportLocalIssuingCaInitializer):

    _private_key: bytes
    _issuing_ca_certificate: bytes
    _additional_certificates: bytes | None

    def __init__(
            self,
            unique_name: str,
            private_key_raw: bytes,
            password: None | bytes,
            issuing_ca_certificate_raw: bytes,
            additional_certificates_raw: bytes | None) -> None:

        self.password = password

        self._unique_name = unique_name
        self._private_key = private_key_raw
        self._issuing_ca_certificate = issuing_ca_certificate_raw
        self._additional_certificates = additional_certificates_raw

    def _construct_credential_serializer(self) -> None:

        if self._additional_certificates:
            additional_certificates = self._certificate_collection_serializer_class.from_bytes(
                self._additional_certificates).as_crypto()
        else:
            additional_certificates = None

        self._credential_serializer = self._credential_serializer_class(
            credential_private_key=self._private_key_serializer_class.from_bytes(
                self._private_key, self._password).as_crypto(),
            credential_certificate=self._certificate_serializer_class.from_bytes(
                self._issuing_ca_certificate).as_crypto(),
            additional_certificates=additional_certificates,
        )
