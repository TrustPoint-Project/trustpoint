"""Simple CSR and subject + private key singing request messages for REST/internal use."""

from __future__ import annotations


import base64
from cryptography import x509

from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    Protocol,
    MimeType,
    ContentTransferEncoding,
    HttpStatusCode,
    Operation)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class RestOperation(Operation):
    ISSUE_CERT_CSR = 'issue_cert_csr'
    ISSUE_CERT_PUBKEY = 'issue_cert_pubkey'

class PkiRestCsrRequestMessage(PkiRequestMessage):
    _csr = x509.CertificateSigningRequest

    def __init__(self,
                 domain_unique_name: str,
                 csr: x509.CertificateSigningRequest):
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

        # TODO: check domain configurations, if protocol and operation are enabled


    def _init_domain_model(self, domain_unique_name: str) -> None:
        try:
            self._domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
        except DomainModel.DoesNotExist:
            self._build_domain_does_not_exist()
            self._is_valid = False
            raise ValueError

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

    def _build_domain_does_not_exist(self) -> None:
        error_msg = f'Domain {self._domain_unique_name} does not exist.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    @property
    def csr(self) -> x509.CertificateSigningRequest:
        return self._csr
