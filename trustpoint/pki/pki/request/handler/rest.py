from __future__ import annotations

import datetime
import base64
import abc

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12, Encoding, NoEncryption
from cryptography.x509.oid import NameOID

from pki.pki.request.message import PkiResponseMessage, HttpStatusCode, MimeType
from pki.pki.request.handler import CaRequestHandler
from pki.models import CertificateModel

from util.x509.enrollment import Enrollment

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message.rest import PkiRestCsrRequestMessage, PkiRestPkcs12RequestMessage
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
            raw_response=cert.public_bytes(Encoding.PEM),
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKCS7_CERTS_ONLY,
            cert_model=cert_model)

    def _get_certificate_builder_from_csr(self) -> x509.CertificateBuilder:
        csr = self._request_message.csr
        cert_builder = x509.CertificateBuilder()
        # Build new subject x509.Name, adding serial number
        attributes = []
        for attribute in csr.subject:
            if attribute.oid != x509.NameOID.SERIAL_NUMBER:
                attributes.append(attribute)
        if not csr.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER):
            serial_number = self._request_message.serial_number
            attributes.append(x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, serial_number))
        cert_builder = cert_builder.subject_name(x509.Name(attributes))
        cert_builder = cert_builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
        cert_builder = cert_builder.not_valid_after(datetime.datetime.today() + ONE_DAY * 365)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.public_key(csr.public_key())
        for extension in csr.extensions:
            cert_builder = cert_builder.add_extension(extension.value, critical=extension.critical)
        if not Enrollment.get_extension_for_oid_or_none(csr.extensions, x509.ExtensionOID.BASIC_CONSTRAINTS):
            cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        return cert_builder
    

class LocalCaRestPkcs12RequestHandler(CaRequestHandler):
    _request_message: PkiRestPkcs12RequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def process_request(self) -> PkiResponseMessage:
        private_key = Enrollment.generate_key('SECP256R1')
        public_key = private_key.public_key()

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(self._request_message._subject)
        cert_builder = cert_builder.issuer_name(self._issuing_ca.issuer_name)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
        cert_builder = cert_builder.not_valid_after(datetime.datetime.today() + ONE_DAY * 365)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.public_key(public_key)
        cert_builder = cert_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=hashes.SHA256())

        cert_model = CertificateModel.save_certificate(certificate=cert)

        pkcs12_bundle = pkcs12.serialize_key_and_certificates(
            name=self._request_message._subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value.encode(),
            key=private_key,
            cert=cert,
            cas=[self._issuing_ca.get_issuing_ca_certificate_serializer().as_crypto()],
            encryption_algorithm=NoEncryption()
        )

        return PkiResponseMessage(
            raw_response=pkcs12_bundle,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKCS12,
            cert_model=cert_model)
