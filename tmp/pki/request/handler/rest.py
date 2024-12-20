from __future__ import annotations

import datetime
import abc

from cryptography import x509

from pki.pki.request.message import PkiResponseMessage, HttpStatusCode, MimeType
from pki.pki.request.handler import CaRequestHandler
from pki.models import CertificateModel
from core.serializer import CertificateSerializer, CredentialSerializer
from pki.util.keys import KeyGenerator, SignatureSuite

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
    from pki.pki.request.message.rest import PkiRestCsrRequestMessage, PkiRestPkcs12RequestMessage
    from pki.issuing_ca import UnprotectedLocalIssuingCa


ONE_DAY = datetime.timedelta(1, 0, 0)


class CaRestRequestHandler(CaRequestHandler, abc.ABC):
    _issuing_ca: UnprotectedLocalIssuingCa

    def _ldevid_build_subject(self, csr: x509.CertificateSigningRequest | None = None) -> x509.Name:
        # Build new subject x509.Name, adding serial number
        domain_name = self._request_message.domain_model.unique_name
        serial_number = self._request_message.serial_number
        device_name = self._request_message.device_name
        attributes = [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Trustpoint LDevID'),
            x509.NameAttribute(x509.NameOID.PSEUDONYM, device_name),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, serial_number),
            x509.NameAttribute(x509.NameOID.DN_QUALIFIER, f'trustpoint.local.{domain_name}')
        ]
        # Do not include anything else for LDevID certs. At least for now!
        # if csr:
        #     for attribute in csr.subject:
        #         if attribute.oid != x509.NameOID.SERIAL_NUMBER or attribute.oid != x509.NameOID.COMMON_NAME:
        #             attributes.append(attribute)

        return x509.Name(attributes)

    def _ldevid_add_common_cert_components(
            self,
            cb: x509.CertificateBuilder,
            pk: CertificatePublicKeyTypes) -> x509.CertificateBuilder:
        cb = cb.public_key(pk)
        cb = cb.not_valid_before(datetime.datetime.today() - ONE_DAY)
        cb = cb.not_valid_after(datetime.datetime.today() + ONE_DAY * 365)
        cb = cb.serial_number(x509.random_serial_number())
        try:
            cb = cb.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        except ValueError: # BasicConstraints already set
            pass

        cb = cb.issuer_name(self._issuing_ca.subject_name)
        return cb


class LocalCaRestCsrRequestHandler(CaRestRequestHandler):
    _request_message: PkiRestCsrRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    # TODO: Validation if Certificate is allowed to be issued
        # TODO: check if certificate was already issued etc.
    # TODO: Store issued certificate in DB
    def process_request(self) -> PkiResponseMessage:
        cert_builder = self._get_certificate_builder_from_csr()
        # cert_builder = cert_builder.issuer_name(self._issuing_ca.subject_name)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=self._request_message.csr.signature_hash_algorithm)

        cert_model = CertificateModel.save_certificate(certificate=cert)

        serializer = CertificateSerializer(cert)

        # TODO: PKIResponseMessage assumes HTTP response, here we need to return the CertificateModel instance
        return PkiResponseMessage(
            raw_response=serializer.as_pem(),
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKCS7_CERTS_ONLY,
            cert_model=cert_model)

    def _get_certificate_builder_from_csr(self) -> x509.CertificateBuilder:
        csr = self._request_message.csr
        cert_builder = x509.CertificateBuilder()
        subject = self._ldevid_build_subject(csr)
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = self._ldevid_add_common_cert_components(cert_builder, csr.public_key())
        for extension in csr.extensions:
            try:
                cert_builder = cert_builder.add_extension(extension.value, critical=extension.critical)
            except ValueError: # Ignore duplicate extensions
                pass
        return cert_builder
    

class LocalCaRestPkcs12RequestHandler(CaRestRequestHandler):
    _request_message: PkiRestPkcs12RequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def process_request(self) -> PkiResponseMessage:
        signature_suite = SignatureSuite.get_signature_suite_by_public_key(
            self._issuing_ca.get_issuing_ca_public_key_serializer().as_crypto())
        private_key = KeyGenerator(signature_suite).generate_key()
        public_key = private_key.public_key()

        cert_builder = x509.CertificateBuilder()
        subject = self._ldevid_build_subject()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = self._ldevid_add_common_cert_components(cert_builder, public_key)
        cert = cert_builder.sign(
            private_key=self._issuing_ca.private_key,
            algorithm=SignatureSuite.get_hash_algorithm_by_key(public_key))

        cert_model = CertificateModel.save_certificate(certificate=cert)

        serializer = CredentialSerializer((private_key, cert, cert_model.get_certificate_chain_serializers(False)[0]))

        return PkiResponseMessage(
            raw_response=serializer.as_pkcs12(),
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKCS12,
            cert_model=cert_model)
