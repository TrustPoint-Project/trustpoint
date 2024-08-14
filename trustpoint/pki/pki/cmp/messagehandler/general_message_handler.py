from pyasn1.type import univ
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from pyasn1.codec.der import decoder

import os
from pki.pki.cmp.builder.pki_body_creator import PkiBodyCreator
from pki.pki.cmp.builder.pki_message_creator import PKIMessageCreator
from pki.pki.cmp.builder.pki_header_creator import PKIHeaderCreator
from pki.pki.cmp.errorhandling.pki_failures import BadRequest
from pyasn1_modules import rfc4210, rfc2459, rfc5914, rfc5280

from pki.pki.cmp.validator.general_message_validator import GeneralMessageValidator


class GeneralMessageHandler:
    def __init__(self, body, header, pki_body_type, protection):
        """
        Initialize the GeneralMessageHandler with the necessary components.

        :param body: univ.Sequence, the incoming body.
        :param header: univ.Sequence, the header of the incoming PKI message.
        :param pki_body_type: PKIBodyTypes, the PKI body type information.
        :param protection: RFC4210Protection, the protection information.
        """
        self.body = body
        self.incoming = self.body.getComponentByName(pki_body_type.request_short_name)
        self.header = header
        self.pki_body_type = pki_body_type
        self.protection = protection

        #self._validate()

    def _validate(self):
        validate_ir = GeneralMessageValidator(self.body)
        validate_ir.validate()

    def handle(self):
        """
        Handles the general message (genm) and generates a corresponding general response (genp).

        :return: str, the response PKI message.
        """
        oid = self._get_oid()
        handler_method = self._get_handler_method(oid)

        if handler_method is None:
            raise BadRequest(f"Unsupported InfoTypeAndValue OID: {oid}")

        response_value = handler_method(oid)

        return self._create_response_pki_message(response_value)

    def _get_oid(self):
        """
        Retrieves the Object Identifier (OID) from the incoming message.

        :return: univ.ObjectIdentifier, the OID of the incoming message.
        """
        info_type_and_value = self.incoming.getComponentByPosition(0)
        return info_type_and_value.getComponentByName('infoType')

    def _get_handler_method(self, oid):
        """
        Maps the OID to the corresponding handler method.

        :param oid: univ.ObjectIdentifier, the OID of the incoming message.
        :return: method, the corresponding handler method.
        """
        handlers = {
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.17'): self.get_ca_certificates,
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.19'): self.get_certificate_request_template,
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.20'): self.get_root_ca_certificate_update,
            univ.ObjectIdentifier('1.3.6.1.5.5.7.4.23'): self.get_new_crls,
        }
        return handlers.get(oid)

    def _create_response_pki_message(self, response_value):
        """
        Creates the response PKI message.

        :param response_value: The value to be included in the response PKI message.
        :return: str, the created response PKI message.
        """
        pki_body = self._create_pki_body(response_value)
        pki_header = self._create_pki_header()

        response_protection = self.protection.compute_protection(pki_header, pki_body)

        pki_message_creator = PKIMessageCreator(pki_body, pki_header, self.pki_body_type, response_protection)
        return pki_message_creator.create_pki_message()

    def _create_pki_body(self, response_value):
        """
        Helper method to create the PKI body for the response.

        :param response_value: The value to be included in the PKI body.
        :return: PKIBody, the created PKI body.
        """
        body_creator = PkiBodyCreator()
        body_creator.set_body_type(self.pki_body_type)
        body_creator.set_info_value(response_value)
        return body_creator.create_pki_body(int_status=0)

    def _create_pki_header(self):
        """
        Helper method to create the PKI header for the response.

        :return: PKIHeader, the created PKI header.
        """
        header_creator = PKIHeaderCreator(self.header, self.protection.ca_cert)
        return header_creator.create_header()

    def info_type_value_builder(self, oid, response_objects):
        """
        Builds an InfoTypeAndValue sequence.

        :param oid: univ.ObjectIdentifier, the OID to set.
        :param response_objects: list, the list of objects to include in the sequence.
        :return: InfoTypeAndValue, the built InfoTypeAndValue object.
        """
        info_type_and_value = rfc4210.InfoTypeAndValue()
        response_seq = univ.Sequence()

        for i, response_object in enumerate(response_objects):
            response_seq[i] = response_object

        info_type_and_value.setComponentByName("infoValue", response_seq)
        info_type_and_value.setComponentByName("infoType", oid)

        return info_type_and_value

    def _load_and_decode_certificate(self, file_path, asn1_spec):
        """
        Helper method to load and decode a certificate from a file.

        :param file_path: str, the path to the certificate file.
        :param asn1_spec: ASN.1 spec, the ASN.1 specification for decoding.
        :return: list, a list of decoded certificates.
        """
        with open(file_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), backend=default_backend())

        der_cert = cert.public_bytes(serialization.Encoding.DER)
        cmp_certificate, _ = decoder.decode(der_cert, asn1_spec)

        return [cmp_certificate]

    def _load_and_decode_crl(self, file_path, asn1_spec):
        """
        Helper method to load and decode a certificate from a file.

        :param file_path: str, the path to the certificate file.
        :param asn1_spec: ASN.1 spec, the ASN.1 specification for decoding.
        :return: list, a list of decoded certificates.
        """
        with open(file_path, "rb") as cert_file:
            crl = x509.load_pem_x509_crl(
                cert_file.read(),
                backend=default_backend()
            )

        der_crl = crl.public_bytes(serialization.Encoding.DER)
        decoded_crl, _ = decoder.decode(der_crl, asn1_spec)

        return [decoded_crl]

    def get_ca_certificates(self, oid):
        """
        Retrieves CA certificates for the response.

        :param oid: univ.ObjectIdentifier, the OID of the request.
        :return: univ.SequenceOf, the sequence of CA certificates.
        """
        certs_path = self._get_cert_path("ca_cert.pem")
        return self.info_type_value_builder(oid,
                                            self._load_and_decode_certificate(certs_path, rfc4210.CMPCertificate()))

    def get_root_ca_certificate_update(self, oid):
        """
        Retrieves the root CA certificate update.

        :param oid: univ.ObjectIdentifier, the OID of the request.
        :return: univ.SequenceOf, the sequence of updated root CA certificates.
        """
        certs_path = self._get_cert_path("ca_cert.pem")
        return self.info_type_value_builder(oid,
                                            self._load_and_decode_certificate(certs_path, rfc4210.CMPCertificate()))

    def get_certificate_request_template(self, oid):
        """
        Retrieves the certificate request template.

        :param oid: univ.ObjectIdentifier, the OID of the request.
        :return: univ.SequenceOf, the certificate request template.
        """
        # TODO: Implement logic to retrieve certificate request template
        pass

    def get_new_crls(self, oid):
        """
        Retrieves new Certificate Revocation Lists (CRLs).

        :param oid: univ.ObjectIdentifier, the OID of the request.
        :return: univ.SequenceOf, the sequence of new CRLs.
        """
        crl_path = self._get_cert_path("ca_crl.pem")
        return self.info_type_value_builder(oid, self._load_and_decode_crl(crl_path, rfc5280.CertificateList()))

    def _get_cert_path(self, filename):
        """
        Helper method to construct the certificate file path.

        :param filename: str, the filename of the certificate.
        :return: str, the full path to the certificate file.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.abspath(os.path.join(script_dir, "..", "..", "certs", filename))

