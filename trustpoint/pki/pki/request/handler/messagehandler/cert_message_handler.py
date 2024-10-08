import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc2459, rfc5280
import datetime
import logging

from pki.models import CertificateModel
from pki.pki.cmp.builder import PkiBodyCreator, PKIMessageCreator, PKIHeaderCreator, ExtraCerts
from pki.pki.cmp.validator import ExtraCertsValidator, InitializationReqValidator


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
        self.cert_request_template = None

        # self._validate()
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

    def configure_request_template(self, cert_request_template):
        """
        Configures the certificate request template.

        :param cert_request_template: The certificate request template.
        """
        self.cert_request_template = cert_request_template

    def handle(self, issuing_ca_object) -> bytes:
        """
        Handles the certificate request and generates an appropriate response PKI message.

        :param issuing_ca_object: The IssuingCa object.
        :return: bytes, the response PKI message.
        """
        self.logger.info("Handling certificate request.")
        self._initialize_ca_data(issuing_ca_object)

        cert_req_msg = self._get_cert_req_msg()
        subject_name, san_list, public_key = self._process_cert_request(cert_req_msg)

        cert = self._generate_and_store_certificate(subject_name, san_list, public_key)

        pki_message = self._generate_pki_response(cert_req_msg, cert)

        self.logger.info("Certificate request handled successfully.")
        return pki_message

    def _initialize_ca_data(self, issuing_ca_object):
        """
        Initializes CA-related data needed for certificate issuance.

        :param issuing_ca_object: The IssuingCa object.
        """
        self.issuing_ca_object = issuing_ca_object
        self.ca_cert = issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()
        self.ca_key = issuing_ca_object.private_key
        root_cert = issuing_ca_object.issuing_ca_model.root_ca_certificate.get_certificate_serializer().as_crypto()
        # TODO: Implement logic to create certificate chain
        self.ca_cert_chain = [root_cert, self.ca_cert]
        self.logger.debug("Initialized CA data.")

    def _process_cert_request(self, cert_req_msg):
        """
        Processes the certificate request message to extract subject, SAN, and public key information.

        :param cert_req_msg: The certificate request message.
        :return: Tuple containing the subject name, SAN list, and public key.
        """
        subject_update = self._update_subject(cert_req_msg)
        extensions_update = self._update_san(cert_req_msg)

        self.logger.debug("Preparing subject and SAN for the certificate.")
        subject_name = self._prepare_subject(subject_update)
        san_list = self._prepare_san(extensions_update)
        public_key = self._prepare_public_key(cert_req_msg)

        return subject_name, san_list, public_key

    def _generate_and_store_certificate(self, subject_name, san_list, public_key):
        """
        Generates and stores the signed certificate.

        :param subject_name: The subject name information.
        :param san_list: The Subject Alternative Names (SAN) for the certificate.
        :param public_key: The public key for the certificate.
        :return: The generated certificate.
        """
        self.logger.debug("Generating signed certificate.")
        cert = self._generate_signed_certificate(subject_name, san_list, public_key, self.ca_cert, self.ca_key)

        self.logger.debug("Saving the certificate in the database.")
        CertificateModel.save_certificate(certificate=cert)

        return cert

    def _generate_pki_response(self, cert_req_msg, cert):
        """
        Generates the PKI response message including the header, body, and protection.

        :param cert_req_msg: The certificate request message.
        :param cert: The signed certificate.
        :return: The PKI message as bytes.
        """
        cert_pem = self._serialize_client_cert(cert)

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

        return pki_message

    def _update_subject(self, cert_req_msg):
        """
        Updates the subject information based on the provided template.

        :param cert_req_msg: The certificate request message.
        :return: The final subject.
        """
        client_cert_template = cert_req_msg.getComponentByName('certTemplate')
        client_subject = client_cert_template.getComponentByName('subject')

        if self.cert_request_template:
            subject_final = rfc2459.Name()
            template_info_value = self.cert_request_template.getComponentByName('infoValue')
            template_cert_template = template_info_value.getComponentByName('certTemplate')
            template_subject = template_cert_template.getComponentByName('subject')

            template_rdn_sequence = template_subject.getComponentByName('')
            client_rdn_sequence = client_subject.getComponentByPosition(0)

            rdn_final_sequence = rfc2459.RDNSequence()

            for template_rdn in template_rdn_sequence:
                template_attr = template_rdn[0]
                template_oid = template_attr.getComponentByName('type')
                template_value = template_attr.getComponentByName('value')

                client_value = None
                for id, client_rdn in enumerate(client_rdn_sequence):
                    client_attr = client_rdn[0]
                    client_oid = client_attr.getComponentByName('type')
                    if client_oid == template_oid:
                        client_value = client_attr.getComponentByName('value')
                        break

                if template_value.prettyPrint() != '':
                    encoded_value = encoder.encode(template_value)
                    final_value = rfc2459.AttributeValue()
                    final_value._value = encoded_value
                elif client_value is not None:
                    final_value = client_value
                else:
                    raise ValueError(f"Required OID {template_oid.prettyPrint()} not found in client subject")

                final_attr = rfc2459.AttributeTypeAndValue()
                final_attr.setComponentByName('type', template_oid)
                final_attr.setComponentByName('value', final_value)

                final_rdn = rfc2459.RelativeDistinguishedName()
                final_rdn.setComponentByPosition(0, final_attr)

                rdn_final_sequence.setComponentByPosition(len(rdn_final_sequence), final_rdn)

            subject_final.setComponentByName('', rdn_final_sequence)

        else:
            subject_final = client_subject

        return subject_final

    def _update_san(self, cert_req_msg):
        """
        Updates the Subject Alternative Name (SAN) extension based on the provided template.

        :param cert_req_msg: The certificate request message.
        :return: The final extensions.
        """
        client_cert_template = cert_req_msg.getComponentByName('certTemplate')
        client_extensions = client_cert_template.getComponentByName('extensions')

        if not self.cert_request_template:
            return client_extensions

        extensions_final = rfc2459.Extensions()
        template_info_value = self.cert_request_template.getComponentByName('infoValue')
        template_cert_template = template_info_value.getComponentByName('certTemplate')
        template_extensions = template_cert_template.getComponentByName('extensions')

        client_general_names = None

        # Find the client's SAN extension and decode it if present
        for client_extension in client_extensions:
            if client_extension.getComponentByName('extnID') == rfc5280.id_ce_subjectAltName:
                client_extn_value = client_extension.getComponentByName('extnValue')
                if isinstance(client_extn_value, univ.OctetString):
                    client_general_names, _ = decoder.decode(bytes(client_extn_value), asn1Spec=rfc5280.GeneralNames())
                    print("Client GeneralNames:", client_general_names.prettyPrint())
                break

        for template_extension in template_extensions:
            extn_id = template_extension.getComponentByName('extnID')
            extn_value = template_extension.getComponentByName('extnValue')
            extn_critical = template_extension.getComponentByName('critical')

            if extn_id == rfc5280.id_ce_subjectAltName:
                octet_bytes = bytes(extn_value)
                template_general_names, _ = decoder.decode(octet_bytes, asn1Spec=rfc5280.GeneralNames())
                final_general_names = rfc5280.GeneralNames()

                for general_name in template_general_names:
                    general_name_type = general_name.getComponent()
                    general_name_name = general_name.getName()

                    if general_name_type.prettyPrint() == '' and client_general_names:
                        match_found = False
                        for client_general_name in client_general_names:
                            if client_general_name.getName() == general_name_name:
                                updated_general_name = rfc5280.GeneralName()
                                updated_general_name.setComponentByName(
                                    general_name_name,
                                    client_general_name.getComponentByName(general_name_name)
                                )
                                final_general_names.append(updated_general_name)
                                match_found = True
                                break

                        if not match_found:
                            raise ValueError(
                                f"Required GeneralName {general_name_name} not found in client GeneralNames")

                    else:
                        final_general_names.append(general_name)

                final_extn_value = univ.OctetString(encoder.encode(final_general_names))
            else:
                final_extn_value = extn_value  # Use the original value if it's not a SAN extension

            # Create the final extension and add it to the final extensions sequence
            final_extension = rfc2459.Extension()
            final_extension.setComponentByName('extnID', extn_id)
            final_extension.setComponentByName('critical', extn_critical)
            final_extension.setComponentByName('extnValue', final_extn_value)

            extensions_final.setComponentByPosition(len(extensions_final), final_extension)

        return extensions_final


    def _prepare_subject(self, subject):
        """
        Prepares the Subject Alternative Names (SAN) for the certificate.

        :param extensions: The extensions information.
        :return: A list of x509.SubjectAlternativeName objects.
        """
        subject_name = []

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

        return subject_name

    def _prepare_san(self, extensions):
        san_list = []

        for extension in extensions:
            extn_id = extension.getComponentByName('extnID')
            if extn_id == rfc2459.id_ce_subjectAltName:
                extn_value = extension.getComponentByName('extnValue')
                san, _ = decoder.decode(extn_value, asn1Spec=rfc5280.GeneralNames())
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

        return san_list

    def _prepare_public_key(self, cert_req_msg):
        """
        Prepares the public key for the certificate.

        :param cert_req_msg: The certificate request message.
        :return: The public key object.
        """
        cert_template = cert_req_msg.getComponentByName('certTemplate')

        public_key_info = cert_template.getComponentByName('publicKey')

        public_key_der = public_key_info.getComponentByName('subjectPublicKey').asOctets()
        public_key = load_der_public_key(public_key_der, backend=default_backend())

        return public_key

    def _generate_signed_certificate(self, subject_name, san_list, public_key, ca_cert, ca_key):
        """
        Generates a signed certificate.

        :param subject_name: The subject's name information.
        :param san_list: The Subject Alternative Names (SAN) for the certificate.
        :param public_key: The public key for the certificate.
        :param ca_cert: The CA certificate.
        :param ca_key: The CA's private key.
        :return: The signed certificate.
        """
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

        return cert

    def _serialize_client_cert(self, client_cert: Certificate) -> bytes:
        """
        Returns the serialized client certificate in DER format.

        :param client_cert: The client certificate.
        :return: bytes, the DER-encoded client certificate.
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
        if self.pki_body_type.request_short_name == "ir":
            for cert in self.ca_cert_chain:
                body_creator.add_ca_pub(ca_cert=cert)
        return body_creator.create_pki_body(cert_pem=cert_pem)

    def _create_pki_header(self):
        """
        Helper method to create the PKI header for the response.

        :return: PKIHeader, the created PKI header.
        """
        header_creator = PKIHeaderCreator(self.header, self.issuing_ca_object)
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

    def _create_pki_message(self, pki_body, pki_header, response_protection, extra_certs=None) -> bytes:
        """
        Helper method to create the PKI message for the response.

        :param pki_body: The PKI body of the message.
        :param pki_header: The PKI header of the message.
        :param response_protection: The computed protection for the message.
        :param extra_certs: Optional extra certificates to include in the message.
        :return: str, the created PKI message.
        """
        pki_message_creator = PKIMessageCreator(pki_body, pki_header, self.pki_body_type, response_protection,
                                                extraCerts=extra_certs)
        return pki_message_creator.create_pki_message()
