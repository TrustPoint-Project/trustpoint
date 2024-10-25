"""Simple CSR and subject + private key singing request messages for REST/internal use."""

from __future__ import annotations


import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    MimeType,
    HttpStatusCode)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


# class RestOperation(Operation):
#     ISSUE_CERT_CSR = 'issue_cert_csr'
#     ISSUE_CERT_PKCS12 = 'issue_cert_pkcs12'


class PkiRestRequestMessage(PkiRequestMessage):
    _mimetype: MimeType = MimeType.TEXT_PLAIN
    _content_transfer_encoding = None
    _content_length_max = 65.536

    def _parse_content(self):
        pass


class PkiRestCsrRequestMessage(PkiRestRequestMessage):
    _csr = x509.CertificateSigningRequest
    _serial_number = str

    def __init__(self,
                 domain_model: DomainModel,
                 csr: x509.CertificateSigningRequest,
                 serial_number: str):
        super().__init__(
            domain_model=domain_model,
            raw_content=None,
            received_mimetype=None,
            received_content_transfer_encoding=None)

        try:
            self._init_csr(csr)
        except ValueError:
            return

        try:
            self._serial_number = serial_number
        except ValueError:
            return

    # TODO: check domain configurations, if protocol and operation are enabled


    # TODO(AlexHx8472): This does not make sense I think, there can't be any exception here, the raw bytes
    # TODO(AlexHx8472): The raw bytes should be passed and the csr should be parsed here.
    # TODO(AlexHx8472): The serial number should not be an attribute -> access parsed data directly
    def _init_csr(self, csr: x509.CertificateSigningRequest) -> None:
        try:
            self._csr = csr
        except ValueError:
            self._build_malformed_csr_response()
            self._is_valid = False
            raise ValueError

    def _build_missing_csr_response(self) -> None:
        error_msg = 'Missing CSR in REST CSR-based certificate issue request.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _build_malformed_csr_response(self) -> None:
        error_msg = f'Failed to parse CSR. Does not seem to be a PKCS#10 CSR.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    @property
    def csr(self) -> x509.CertificateSigningRequest:
        return self._csr

    @property
    def serial_number(self) -> str:
        return self._serial_number


class PkiRestPkcs12RequestMessage(PkiRestRequestMessage):
    _serial_number = str

    def __init__(self,
                 domain_model: DomainModel,
                 serial_number: str):
        super().__init__(
            domain_model=domain_model,
            raw_content=None,
            received_mimetype=None,
            received_content_transfer_encoding=None)
        
        try:
            self._serial_number = serial_number
        except ValueError:
            return
        
    @property
    def serial_number(self) -> str:
        return self._serial_number