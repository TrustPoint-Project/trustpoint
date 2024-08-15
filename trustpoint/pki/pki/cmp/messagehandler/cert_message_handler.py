import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
import datetime
import logging

from pki.pki.cmp.builder.pki_body_creator import PkiBodyCreator
from pki.pki.cmp.builder.pki_message_creator import PKIMessageCreator
from pki.pki.cmp.builder.pki_header_creator import PKIHeaderCreator
from pki.pki.cmp.builder.extra_certs import ExtraCerts
from pki.pki.cmp.validator.extracerts_validator import ExtraCertsValidator
from pki.pki.cmp.validator.initialization_req_validator import InitializationReqValidator


class CertMessageHandler:
    def __init__(self, body, header, pki_body_type, protection, domain=None):
        """
        Initialize the CertMessageHandler with the necessary components.

        :param body: univ.Sequence, the incoming body.
        :param header: univ.Sequence, the header of the incoming PKI message.
        :param pki_body_type: PKIBodyTypes, the PKI body type information.
        :param protection: RFC4210Protection, the protection information.
        :param domain: str, the domain related to the request.
        """
        self.body = body
        self.incoming = body.getComponentByName(pki_body_type.request_short_name)
        self.header = header
        self.pki_body_type = pki_body_type
        self.protection = protection
        self.domain = domain
        self.ca_cert = None
        self.issuing_ca_object = None
        self.ca_cert_chain = None

        #self._validate()
        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Adjust logging level as needed
        self.logger.info("CertMessageHandler initialized for domain: %s", domain)

    def _validate(self):
        """
        Validates the initialization request using InitializationReqValidator.
        """
        self.logger.debug("Validating initialization request.")
        validator = InitializationReqValidator(self.body)
        validator.validate()
        self.logger.debug("Validation completed.")

    def handle(self, issuing_ca_object):
        """
        Handles the certificate request and generates an appropriate response PKI message.

        :param issuing_ca_object: The IssuingCa object.
        :return: str, the response PKI message.
        """
        self.logger.info("Handling certificate request.")
        self.ca_cert = issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()
        self.ca_key = issuing_ca_object.private_key
        root_cert = issuing_ca_object.issuing_ca_model.root_ca_certificate.get_certificate_serializer().as_crypto()
        self.ca_cert_chain = [root_cert, self.ca_cert]

        cert_req_msg = self._get_cert_req_msg()

        self.logger.debug("Preparing subject and SAN for the certificate.")
        subject_name, san_list, public_key = self._prepare_subject_san(cert_req_msg)

        self.logger.debug("Generating signed certificate.")
        cert_pem = self._generate_signed_certificate(subject_name, san_list, public_key, self.ca_cert, self.ca_key)

        self.logger.debug("Creating PKI body.")
        pki_body = self._create_pki_body(cert_req_msg, cert_pem, self.ca_cert)

        self.logger.debug("Creating PKI header.")
        pki_header = self._create_pki_header()

        self.logger.debug("Handling extra certificates.")
        extra_certs = self._handle_extra_certs(self.ca_cert)

        self.logger.debug("Computing response protection.")
        response_protection = self.protection.compute_protection(pki_header, pki_body)

        self.logger.debug("Creating PKI message.")
        pki_message = self._create_pki_message(pki_body, pki_header, response_protection, extra_certs)

        self.logger.info("Certificate request handled successfully.")
        return pki_message

    def _prepare_subject_san(self, cert_req_msg):
        subject_name = []
        san_list = []

        cert_template = cert_req_msg.getComponentByName('certTemplate')

        subject = cert_template.getComponentByName('subject')

        public_key_info = cert_template.getComponentByName('publicKey')

        public_key_der = public_key_info.getComponentByName('subjectPublicKey').asOctets()
        public_key = load_der_public_key(public_key_der, backend=default_backend())

        extensions = cert_template.getComponentByName('extensions')

        for extension in extensions:
            extn_id = extension.getComponentByName('extnID')
            if extn_id == rfc2459.id_ce_subjectAltName:
                extn_value = extension.getComponentByName('extnValue')
                san, _ = decoder.decode(extn_value, asn1Spec=rfc2459.SubjectAltName())
                for general_name in san:
                    name_type = general_name.getName()
                    if name_type == 'dNSName':
                        san_list.append(x509.DNSName(str(general_name.getComponent())))
                    elif name_type == 'iPAddress':
                        binary_ip = general_name.getComponent().asOctets()
                        ip_address = ipaddress.ip_address(binary_ip)
                        san_list.append(x509.IPAddress(ip_address))
                    elif name_type == 'uniformResourceIdentifier':
                        san_list.append(x509.UniformResourceIdentifier(str(general_name.getComponent())))

        for rdn in subject[0]:
            for atv in rdn:

                oid = atv.getComponentByName('type')
                value = atv.getComponentByName('value')

                value, _ = decoder.decode(bytes(value))

                # print(f"OID: {oid} ({len(oid)}), Value: >{str(value)}< ({len(str(value))})")
                if oid == rfc2459.id_at_commonName:
                    subject_name.append(x509.NameAttribute(NameOID.COMMON_NAME, str(value)))
                elif oid == rfc2459.id_at_countryName:
                    subject_name.append(x509.NameAttribute(NameOID.COUNTRY_NAME, str(value)))
                elif oid == rfc2459.id_at_stateOrProvinceName:
                    subject_name.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, str(value)))
                elif oid == rfc2459.id_at_localityName:
                    subject_name.append(x509.NameAttribute(NameOID.LOCALITY_NAME, str(value)))
                elif oid == rfc2459.id_at_organizationName:
                    subject_name.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(value)))
                elif oid == rfc2459.id_at_organizationalUnitName:
                    subject_name.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, str(value)))

        return subject_name, san_list, public_key

    def _generate_signed_certificate(self, subject_name, san_list, public_key, ca_cert, ca_key):
        subject = x509.Name(subject_name)

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        )

        if san_list:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(public_key)
        cert_builder = cert_builder.add_extension(
            subject_key_identifier,
            critical=False,
        )

        cert = cert_builder.sign(ca_key, hashes.SHA256())
        cert_pem = self._serialize_client_cert(cert)

        return cert_pem

    def _serialize_client_cert(self, client_cert: Certificate) -> bytes:
        """
        Returns the serialized client certificate in PEM format.

        :return: bytes, the PEM-encoded CA certificate.
        """
        return client_cert.public_bytes(encoding=Encoding.DER)

    def _get_cert_req_msg(self):
        """
        Retrieves the certificate request message from the incoming body.

        :return: The certificate request message.
        """
        cert_req_msg = self.incoming.getComponentByPosition(0)
        cert_req = cert_req_msg.getComponentByName('certReq')
        return cert_req

    def _create_pki_body(self, cert_req_msg, cert_pem, ca_cert):
        """
        Helper method to create the PKI body for the response.

        :param cert_req_msg: The certificate request message.
        :param cert_pem: The signed certificate in PEM format.
        :param ca_cert: The CA certificate.
        :return: PKIBody, the created PKI body.
        """
        body_creator = PkiBodyCreator()
        cert_req_id = cert_req_msg.getComponentByName('certReqId')
        body_creator.set_cert_req_id(cert_req_id)
        body_creator.set_body_type(self.pki_body_type)
        for cert in self.ca_cert_chain:
            body_creator.add_ca_pub(ca_cert=cert)
        return body_creator.create_pki_body(cert_pem=cert_pem)

    def _create_pki_header(self):
        """
        Helper method to create the PKI header for the response.

        :return: PKIHeader, the created PKI header.
        """
        header_creator = PKIHeaderCreator(self.header, self.ca_cert)
        return header_creator.create_header()

    def _handle_extra_certs(self, ca_cert):
        """
        Handles the extra certificates for the response, including validation.

        :param ca_cert: The CA certificate.
        :return: univ.SequenceOf, the extra certificates if any.
        """
        if ca_cert is not None:
            extra_certs = ExtraCerts()
            extra_certs_seq = extra_certs.generate_sequence([ca_cert])

            validator = ExtraCertsValidator(extra_certs_seq, self.protection.protection_mode,
                                            self.pki_body_type.response_short_name)
            validator.validate()

            return extra_certs_seq
        return None

    def _create_pki_message(self, pki_body, pki_header, response_protection, extra_certs=None):
        """
        Helper method to create the PKI message for the response.

        :param pki_body: The PKI body of the message.
        :param pki_header: The PKI header of the message.
        :param response_protection: The computed protection for the message.
        :param extra_certs: Optional extra certificates to include in the message.
        :return: str, the created PKI message.
        """
        pki_message_creator = PKIMessageCreator(pki_body, pki_header, self.pki_body_type, response_protection, extraCerts=extra_certs)
        return pki_message_creator.create_pki_message()


