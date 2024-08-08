from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from .pki_message import PkiEstRequestMessage, PkiEstResponseMessage, EstOperation
from cryptography import x509

from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

import datetime

if TYPE_CHECKING:
    from .issuing_ca import UnprotectedLocalIssuingCa

ONE_DAY = datetime.timedelta(1, 0, 0)


class EstServer(ABC):

    @abstractmethod
    def process_request(self) -> PkiEstResponseMessage:
        pass


class LocalEstServer(EstServer):
    _request_message: PkiEstRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def __init__(self, request_message: PkiEstRequestMessage, issuing_ca: UnprotectedLocalIssuingCa):
        if not isinstance(request_message, PkiEstRequestMessage):
            raise TypeError('Dispatch Error: Local EST Server received a non EST message.')
        # if not isinstance(issuing_ca, UnprotectedLocalIssuingCa):
        #     raise TypeError('Dispatch Error: Local EST Server received a non local issuing ca object.')
        self._request_message = request_message
        self._issuing_ca = issuing_ca

    def process_request(self) -> PkiEstResponseMessage:
        if self._request_message.operation == EstOperation.SIMPLE_ENROLL:
            return self._process_simple_enroll()

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

    def _process_simple_enroll(self) -> PkiEstResponseMessage:
        cert_builder = self._get_certificate_builder_from_csr()
        cert_builder = cert_builder.issuer_name(self._issuing_ca.issuer_name)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=self._request_message.csr.signature_hash_algorithm)
        raw_pkcs7 = pkcs7.serialize_certificates([cert], encoding=Encoding.DER)
        return PkiEstResponseMessage(response=raw_pkcs7, http_status=200, mimetype='application/pkcs7-mime')


class RemoteEstServer(EstServer):
    request_message: PkiEstRequestMessage
