from __future__ import annotations

import base64
import abc
from ..pki_message import (
    PkiRequestMessage,
    PkiResponseMessage,
    PkiEstSimpleEnrollRequestMessage,
    HttpStatusCode,
    MimeType)
from cryptography import x509

from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

import datetime


from ..issuing_ca import UnprotectedLocalIssuingCa

ONE_DAY = datetime.timedelta(1, 0, 0)


class CaRequestHandlerFactory:

    @classmethod
    def get_request_handler(cls, request: PkiRequestMessage) -> CaRequestHandler:

        if isinstance(request, PkiEstSimpleEnrollRequestMessage):
            if isinstance(request.domain_model.issuing_ca.get_issuing_ca(), UnprotectedLocalIssuingCa):
                return LocalEstCaSimpleEnrollRequestHandler(request)


class CaRequestHandler(abc.ABC):

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass


class CaEstRequestHandler(CaRequestHandler):

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass


class LocalEstCaSimpleEnrollRequestHandler(CaEstRequestHandler):
    _request_message: PkiEstSimpleEnrollRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def __init__(self, request: PkiEstSimpleEnrollRequestMessage):
        self._request_message = request
        self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()

    # TODO: Validation if Certificate is allowed to be issued
        # TODO: check if certificate was already issued etc.
    # TODO: Store issued certificate in DB
    def process_request(self) -> PkiResponseMessage:
        cert_builder = self._get_certificate_builder_from_csr()
        cert_builder = cert_builder.issuer_name(self._issuing_ca.issuer_name)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=self._request_message.csr.signature_hash_algorithm)
        raw_pkcs7 = pkcs7.serialize_certificates([cert], encoding=Encoding.DER)
        return PkiResponseMessage(
            raw_response=base64.b64encode(raw_pkcs7),
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKCS7_CERTS_ONLY)

    def _get_certificate_builder_from_csr(self) -> x509.CertificateBuilder:
        csr = self._request_message.csr
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(csr.subject)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
        cert_builder = cert_builder.not_valid_after(datetime.datetime.today() + ONE_DAY * 365)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.public_key(csr.public_key())
        for extension in csr.extensions:
            cert_builder = cert_builder.add_extension(extension.value, critical=extension.critical)
        return cert_builder
