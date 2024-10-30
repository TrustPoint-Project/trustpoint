"""Simple CSR and subject + private key singing request messages for REST/internal use."""
# TODO(AlexHx8472): rework this entire module including the rest message!
from __future__ import annotations

from cryptography import x509

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


class PkiRestRequestMessage(PkiRequestMessage):
    _mimetype: MimeType = MimeType.TEXT_PLAIN
    _content_transfer_encoding = None
    _content_length_max = 65.536

    def _parse_content(self):
        pass


class PkiRestCsrRequestMessage(PkiRestRequestMessage):
    _csr = x509.CertificateSigningRequest
    _serial_number = str
    _device_name = str

    def __init__(self,
                 domain_model: DomainModel,
                 csr: x509.CertificateSigningRequest,
                 serial_number: str,
                 device_name: str):
        super().__init__(
            domain_model=domain_model,
            raw_content=None,
            received_mimetype=None,
            received_content_transfer_encoding=None)

        self._init_csr(csr)
        self._serial_number = serial_number
        self._device_name = device_name

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

    @property
    def device_name(self) -> str:
        return self._device_name


class PkiRestPkcs12RequestMessage(PkiRestRequestMessage):
    _serial_number = str
    _device_name = str

    def __init__(self,
                 domain_model: DomainModel,
                 serial_number: str,
                 device_name: str):
        super().__init__(
            domain_model=domain_model,
            raw_content=None,
            received_mimetype=None,
            received_content_transfer_encoding=None)

        self._serial_number = serial_number
        self._device_name = device_name
        
    @property
    def serial_number(self) -> str:
        return self._serial_number

    @property
    def device_name(self) -> str:
        return self._device_name