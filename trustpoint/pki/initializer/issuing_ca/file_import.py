from __future__ import annotations

import abc
import traceback

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import pkcs12

from pki.models import CertificateModel, IssuingCaModel, CertificateChainOrderModel

from pki.serializer import PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer

from . import IssuingCaInitializer
from . import IssuingCaInitializerError

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class FileImportLocalIssuingCaInitializerError(IssuingCaInitializerError):
    pass


class TooManyCertificatesError(FileImportLocalIssuingCaInitializerError):

    def __init__(self, cert_count: int, limit: int) -> None:
        super().__init__(message=_(
            f'The uploaded file(s) contain more than {cert_count} certificates. '
            f'Refusing to process more than {limit} certificates.'))


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
        super().__init__(message=_(f'Issuing CA already exists. Unique Name: {name}.'))


class FileImportLocalIssuingCaInitializer(IssuingCaInitializer, abc.ABC):

    _CERTIFICATE_UPLOAD_FILE_LIMIT: int = 100


class UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer(FileImportLocalIssuingCaInitializer):
    # TODO: check p12 edge cases
    # TODO: -> no issuing ca certificate, no full chain, no key, ...

    _cert_model_class: type[CertificateModel] = CertificateModel
    _issuing_ca_model_class: type[IssuingCaModel] = IssuingCaModel
    _cert_chain_order_model_class: type[CertificateChainOrderModel] = CertificateChainOrderModel

    _unique_name: str
    _p12: pkcs12
    _password: None | bytes

    _private_key: PrivateKey
    _issuing_ca_certificate: x509.Certificate
    _additional_certificates: list[x509.Certificate]


    def __init__(self, unique_name: str, p12: bytes | pkcs12, password: None | bytes = None) -> None:

        if isinstance(p12, bytes):
            p12 = pkcs12.load_pkcs12(p12, password)

        self._unique_name = unique_name
        self._p12 = p12
        self._password = password


    def initialize(self) -> None:
        self._extract_key()
        self._extract_issuing_ca_certificate()
        self._extract_additional_certificates()

        self._check_certificate_upload_file_limit()

        self._build_full_certificate_chain()

        # self._validate_issuing_ca()

    def _extract_key(self) -> None:
        self._private_key = self._p12.key

    def _extract_issuing_ca_certificate(self) -> None:
        self._issuing_ca_certificate = self._p12.cert.certificate

    def _extract_additional_certificates(self) -> None:
        self._additional_certificates = [cert.certificate for cert in self._p12.additional_certs]

    def _check_certificate_upload_file_limit(self) -> None:
        cert_count = len(self._additional_certificates) + 1
        if cert_count > self._CERTIFICATE_UPLOAD_FILE_LIMIT:
            raise TooManyCertificatesError(
                cert_count=cert_count,
                limit=self._CERTIFICATE_UPLOAD_FILE_LIMIT
            )

    def _build_full_certificate_chain(self) -> None:

        current_cert = self._issuing_ca_certificate
        certs = self._additional_certificates.copy()
        self._full_cert_chain = [self._issuing_ca_certificate]

        # extra flag, if this should be allowed
        if self._is_self_signed(current_cert):
            return

        processed_certs = [current_cert.fingerprint(SHA256())]

        while not self._is_self_signed(current_cert):

            issuer = self._get_issuer_certificate(current_cert, self._additional_certificates)
            certs.remove(issuer)
            fingerprint = self._get_fingerprint(issuer)
            if fingerprint in processed_certs:
                raise CertificateChainContainsCycleError
            processed_certs.append(fingerprint)
            self._full_cert_chain.append(issuer)
            current_cert = issuer

        self._full_cert_chain.reverse()

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

    def _validate_issuing_ca(self) -> None:
        # TODO
        pass

    @transaction.atomic
    def save(self):

        try:
            saved_certs = [self._cert_model_class.save_certificate(self._issuing_ca_certificate)]
        except ValueError:

            cert_model = CertificateModel.objects.get(
                sha256_fingerprint=self._get_fingerprint(self._issuing_ca_certificate).hex().upper())

            if hasattr(cert_model, 'issuing_ca_model'):
                raise IssuingCaAlreadyExistsError(name=cert_model.issuing_ca_model.unique_name)

            saved_certs = [cert_model]

        for certificate in self._full_cert_chain[1:]:
            saved_certs.append(self._cert_model_class.save_certificate(certificate, exist_ok=True))

        issuing_ca_model = self._issuing_ca_model_class(
            unique_name=self._unique_name,
            private_key_pem=PrivateKeySerializer(self._private_key).as_pkcs1_pem(None)
        )

        issuing_ca_model.issuing_ca_certificate = saved_certs[-1]
        issuing_ca_model.root_ca_certificate = saved_certs[0]
        issuing_ca_model.save()

        for number, certificate in enumerate(saved_certs[1:-1]):
            cert_chain_order_model = self._cert_chain_order_model_class()
            cert_chain_order_model.order = number
            cert_chain_order_model.certificate = certificate
            cert_chain_order_model.issuing_ca = issuing_ca_model
            cert_chain_order_model.save()


# class LocalUnprotectedIssuingCaFromSeparateFilesInitializer(LocalIssuingCaFromFileInitializer):
#
#     _unique_name: str
#     _private_key: PrivateKeySerializer
#     _issuing_ca_cert: None | CertificateSerializer
#     _cert_chain: None | CertificateCollectionSerializer
#     _full_cert_chain: CertificateCollectionSerializer
#     _validator: IssuingCaValidator
#
#     def __init__(
#             self,
#             unique_name: str,
#             private_key_file_raw: bytes,
#             password: None | bytes,
#             issuing_ca_cert_raw: bytes,
#             certificate_chain_raw: None | bytes,
#             validator: IssuingCaValidator = IssuingCaValidator,
#             cert_model_class: type(CertificateModel) = CertificateModel,
#             issuing_ca_model_class: type(IssuingCaModel) = IssuingCaModel,
#             cert_chain_order_model: type(CertificateChainOrderModel) = CertificateChainOrderModel
#     ) -> None:
#
#         self._cert_model_class = cert_model_class
#         self._issuing_ca_model_class = issuing_ca_model_class
#         self._cert_chain_order_model = cert_chain_order_model
#
#         self._unique_name = unique_name
#         self._private_key = PrivateKeySerializer.from_bytes(private_key_file_raw, password=password)
#
#         self._issuing_ca_cert = CertificateSerializer.from_bytes(issuing_ca_cert_raw)
#
#         if certificate_chain_raw is None:
#             self._cert_chain = None
#         else:
#             self._cert_chain = CertificateCollectionSerializer.from_bytes(certificate_chain_raw)
#

    #     if not self._issuing_ca_cert:
    #         self._issuing_ca_cert = self._extract_issuing_ca_cert
    #
    #     # self._validate_issuing_ca()
    #
    # def _extract_issuing_ca_cert(self) -> CertificateSerializer:
    #     public_key_from_private_key =
    #     for cert in self._cert_chain.as_crypto():
    #         if
    #
    #
    #
    #
    # def _validate_issuing_ca(self) -> None:
    #     # TODO
    #     pass

    # @transaction.atomic
    # def save(self):
    #
    #     saved_certs = []
    #
    #     for certificate in self._full_cert_chain:
    #         saved_certs.append(self._cert_model_class.save_certificate(certificate))
    #
    #     issuing_ca_model = self._issuing_ca_model_class(
    #         unique_name=self._unique_name,
    #         private_key_pem=self._private_key_pem,
    #     )
    #
    #     issuing_ca_model.issuing_ca_certificate = saved_certs[-1]
    #     issuing_ca_model.root_ca_certificate = saved_certs[0]
    #     issuing_ca_model.save()
    #
    #     for number, certificate in enumerate(saved_certs[1:-1]):
    #         cert_chain_order_model = self._cert_chain_order_model()
    #         cert_chain_order_model.order = number
    #         cert_chain_order_model.certificate = certificate
    #         cert_chain_order_model.issuing_ca = issuing_ca_model
    #         cert_chain_order_model.save()

