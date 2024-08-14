"""Simple CSR and subject + private key singing request messages for REST/internal use."""

from __future__ import annotations


import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    Protocol,
    MimeType,
    HttpStatusCode,
    Operation)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class RestOperation(Operation):
    ISSUE_CERT_CSR = 'issue_cert_csr'
    ISSUE_CERT_PKCS12 = 'issue_cert_pkcs12'

class PkiRestCsrRequestMessage(PkiRequestMessage):
    _csr = x509.CertificateSigningRequest
    _serial_number = str

    def __init__(self,
                 domain_unique_name: str,
                 csr: x509.CertificateSigningRequest,
                 serial_number: str):
        super().__init__(
            protocol=Protocol.REST,
            operation=RestOperation.ISSUE_CERT_CSR,
            domain_unique_name=domain_unique_name)

        try:
            self._init_domain_model(domain_unique_name)
        except ValueError:
            return

        try:
            self._init_csr(csr)
        except ValueError:
            return

        try:
            self._serial_number = serial_number
        except ValueError:
            return

        # TODO: check domain configurations, if protocol and operation are enabled


    

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


class PkiRestPkcs12RequestMessage(PkiRequestMessage):
    _subject = x509.Name

    def __init__(self,
                domain_unique_name: str,
                subject: x509.Name):
        super().__init__(
            protocol=Protocol.REST,
            operation=RestOperation.ISSUE_CERT_PKCS12,
            domain_unique_name=domain_unique_name)
        
        try:
            self._init_domain_model(domain_unique_name)
        except ValueError:
            return
        
        try:
            self._init_subject(subject)
        except ValueError:
            return

    def _init_subject(self, subject: x509.Name) -> None:
        try:
            self._subject = subject
            if not subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER):
                raise ValueError
        except ValueError:
            self._build_malformed_subject_response()
            self._is_valid = False
            raise ValueError
        
    def _build_malformed_subject_response(self) -> None:
        error_msg = f'Subject not an x509.Name or does not contain required attribute OIDs.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)