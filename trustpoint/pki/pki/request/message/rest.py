"""Simple CSR and subject + private key singing request messages for REST/internal use."""
# TODO(AlexHx8472): rework this entire module including the rest message!
from __future__ import annotations

from cryptography import x509
import re
# from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    MimeType,
    HttpStatusCode)

from typing import TYPE_CHECKING

import secrets

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class StringValidator:
    """Contains utility functions for string validation"""

    @staticmethod
    def is_urlsafe(string: str) -> bool:
        """Returns True if string only contains alphanumeric characters and '-' or '_'"""
        p = re.compile(r'[^a-zA-Z0-9\-_]')
        return p.search(string) is None


class PkiRestRequestMessage(PkiRequestMessage):
    _mimetype: MimeType = MimeType.TEXT_PLAIN
    _content_transfer_encoding = None
    _content_length_max = 65.536

    def _parse_content(self):
        pass


class PkiRestCsrRequestMessage(PkiRestRequestMessage):
    _mimetype: MimeType = MimeType.APPLICATION_PKCS10
    _csr = x509.CertificateSigningRequest
    _serial_number: str
    _device_name: str

    def __init__(self,
                 # domain_model: DomainModel,
                 raw_content: bytes,
                 device_name: str,
                 serial_number_expected: str | None = None):
        self._serial_number = serial_number_expected
        self._device_name = device_name
        super().__init__(
            # domain_model=domain_model,
            raw_content=raw_content,
            received_mimetype=MimeType.APPLICATION_PKCS10,
            received_content_transfer_encoding=None)


    def _parse_content(self) -> None:
        try:
            self._csr = x509.load_pem_x509_csr(self._raw_content)
        except ValueError:
            self._build_malformed_csr_response()
            self._is_valid = False
            raise ValueError

        try:
            csr_serial = self._csr.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
        except (x509.ExtensionNotFound, IndexError):
            csr_serial = None

        if not self._serial_number and not csr_serial:
            #log.warning('No serial number provided in CSR for device %s', device.device_name)
            self._serial_number = 'tp_' + secrets.token_urlsafe(12)

        if csr_serial and not StringValidator.is_urlsafe(csr_serial):
            exc_msg = 'Invalid serial number in CSR.'
            raise ValueError(exc_msg)

        if self._serial_number and csr_serial and self._serial_number != csr_serial:
            exc_msg = 'CSR serial number does not match device serial number.'
            raise ValueError(exc_msg)

        self._serial_number = self._serial_number or csr_serial

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
                 # domain_model: DomainModel,
                 serial_number: str,
                 device_name: str):
        self._serial_number = serial_number
        self._device_name = device_name
        super().__init__(
            # domain_model=domain_model,
            raw_content=None,
            received_mimetype=None,
            received_content_transfer_encoding=None)
        
    @property
    def serial_number(self) -> str:
        return self._serial_number

    @property
    def device_name(self) -> str:
        return self._device_name