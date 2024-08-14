from __future__ import annotations

import datetime
import base64
import abc

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

from pki.pki.request.message import PkiResponseMessage, HttpStatusCode, MimeType
from pki.pki.request.handler import CaRequestHandler
from pki.models import CertificateModel

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message.rest import PkiRestCsrRequestMessage
    from pki.issuing_ca import UnprotectedLocalIssuingCa


ONE_DAY = datetime.timedelta(1, 0, 0)


class LocalCaRestCsrRequestHandler(CaRequestHandler):
    _request_message: PkiRestCsrRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    # TODO: Validation if Certificate is allowed to be issued
        # TODO: check if certificate was already issued etc.
    # TODO: Store issued certificate in DB
    def process_request(self) -> PkiResponseMessage:
        cert_builder = self._get_certificate_builder_from_csr()
        cert_builder = cert_builder.issuer_name(self._issuing_ca.issuer_name)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=self._request_message.csr.signature_hash_algorithm)

        cert_model = CertificateModel.save_certificate(certificate=cert)

        # TODO: PKIResponseMessage assumes HTTP response, here we need to return the CertificateModel instance
        return PkiResponseMessage(
            raw_response=cert_model, # TODO: TYPING violation!
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