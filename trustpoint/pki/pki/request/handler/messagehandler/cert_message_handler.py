from __future__ import annotations

import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from cryptography.x509 import ObjectIdentifier
from cryptography.x509 import Certificate
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
from pyasn1_modules import rfc2459, rfc5280
import datetime
import logging
from pyasn1.error import PyAsn1Error

from devices.models import DeviceModel
from devices import CertificateTypes, TemplateName
from pki.models import CertificateModel
from pki.pki.cmp.builder import PkiBodyCreator, PKIMessageCreator, PKIHeaderCreator, ExtraCerts
from pki.pki.cmp.validator import ExtraCertsValidator, InitializationReqValidator
from core.oid import CertificateExtensionOid, NameOid
from pki.util.keys import SignatureSuite


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
        subject_name, public_key, extensions = self._process_cert_request(cert_req_msg)
        valid_not_before, valid_not_after = self._get_validity(cert_req_msg)

        cert = self._generate_and_store_certificate(
            subject_name,
            public_key,
            valid_not_before,
            valid_not_after,
            extensions)

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
        public_key = self._prepare_public_key(cert_req_msg)
        subject_update = self._update_subject(cert_req_msg)
        extensions = self._get_extensions(cert_req_msg)

        self.logger.debug("Preparing subject and SAN for the certificate.")
        subject_name = self._prepare_subject(subject_update)

        return subject_name, public_key, extensions


    @staticmethod
    def _get_validity(cert_req_msg) -> tuple[datetime.datetime, datetime.datetime]:
        validity_field = cert_req_msg.getComponentByName('certTemplate')['validity']
        not_valid_before = validity_field['notBefore'][0].asDateTime
        not_valid_after = validity_field['notAfter'][0].asDateTime
        if not_valid_before >= not_valid_after:
            raise ValueError('Validity fields are corrupted. Found inconsistent times.')
        return not_valid_before, not_valid_after



    def _generate_and_store_certificate(self, subject_name, public_key, valid_not_before, valid_not_after, extensions):
        """
        Generates and stores the signed certificate.

        :param subject_name: The subject name information.
        :param public_key: The public key for the certificate.
        :return: The generated certificate.
        """
        self.logger.debug("Generating signed certificate.")
        cert = self._generate_signed_certificate(
            subject_name,
            public_key,
            self.ca_cert,
            self.ca_key,
            valid_not_before,
            valid_not_after,
            extensions)

        self.logger.debug("Saving the certificate in the database.")
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
                for _, client_rdn in enumerate(client_rdn_sequence):
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


    @staticmethod
    def _prepare_subject(subject) -> list[x509.NameAttribute]:
        """
        Prepares the Subject Alternative Names (SAN) for the certificate.

        :return: A list of x509.SubjectAlternativeName objects.
        """
        subject_name = []

        for rdn in subject[0]:
            for atv in rdn:

                oid = str(atv.getComponentByName('type'))
                value = atv.getComponentByName('value')

                value, _ = decoder.decode(bytes(value))
                subject_name.append(x509.NameAttribute(ObjectIdentifier(oid), str(value)))

        return subject_name

    def _get_extensions(self, cert_req_msg):
        extensions = cert_req_msg.getComponentByName('certTemplate').getComponentByName('extensions')
        supported_oids = {
            rfc2459.id_ce_basicConstraints: self._get_basic_constraints,
            rfc2459.id_ce_keyUsage: self._get_key_usage,
            rfc2459.id_ce_extKeyUsage: self._get_extended_key_usage,
            rfc2459.id_ce_authorityKeyIdentifier: self._get_authority_key_identifier,
            rfc2459.id_ce_subjectKeyIdentifier: self._get_subject_key_identifier,
            rfc2459.id_ce_subjectAltName: self._get_subject_alternative_name
        }
        result = {}
        extension_oids = [extension.getComponentByName('extnID') for extension in extensions]
        for extension in extensions:
            oid_value = extension.getComponentByName('extnID')
            if oid_value not in supported_oids:
                raise ValueError('Extension not supported.')
            result |= supported_oids[oid_value](extension)

        if rfc2459.id_ce_subjectKeyIdentifier not in extension_oids:
            result |= self._set_subject_key_identifier()

        if rfc2459.id_ce_authorityKeyIdentifier not in extension_oids:
            result |= self._set_authority_key_identifier()

        return result

    @staticmethod
    def _get_basic_constraints(extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        value = extension.getComponentByName('extnValue')
        critical = extension.getComponentByName('critical')

        if critical:
            critical = True
        else:
            critical = False

        bc_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.BasicConstraints())
        try:
            if bc_content.getComponentByName('cA'):
                raise ValueError('Issuing CA certificates is not allowed.')
        except (AttributeError, PyAsn1Error):
            pass

        try:
            if bc_content.getComponentByName('pathLenConstraint') != 0:
                raise ValueError('Path length constraint must be 0 if provided.')
        except (AttributeError, PyAsn1Error):
            pass

        crypto_bc_extension = x509.BasicConstraints(ca=False, path_length=None)

        return {
            CertificateExtensionOid.BASIC_CONSTRAINTS: (critical, crypto_bc_extension)
        }

    @staticmethod
    def _get_crypto_extension_by_bit_str(bit_str: str) -> x509.KeyUsage:
        bit_str = bit_str.ljust(9, '0')
        options = {
            'digital_signature': True if bit_str[0] == '1' else False,
            'content_commitment': True if bit_str[1] == '1' else False,
            'key_encipherment': True if bit_str[2] == '1' else False,
            'data_encipherment': True if bit_str[3] == '1' else False,
            'key_agreement': True if bit_str[4] == '1' else False,
            'key_cert_sign': True if bit_str[5] == '1' else False,
            'crl_sign': True if bit_str[6] == '1' else False,
            'encipher_only': True if bit_str[7] == '1' else False,
            'decipher_only': True if bit_str[8] == '1' else False,
        }
        return x509.KeyUsage(**options)

    @classmethod
    def _get_key_usage(cls, extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        critical = extension.getComponentByName('critical')
        if critical:
            critical = True
        else:
            critical = False

        value = extension.getComponentByName('extnValue')
        ku_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.KeyUsage())
        binary_value = ku_content.asBinary()

        key_usage_extension = cls._get_crypto_extension_by_bit_str(binary_value)

        return {
            CertificateExtensionOid.KEY_USAGE: (critical, key_usage_extension)
        }

    @classmethod
    def _get_extended_key_usage(cls, extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        critical = extension.getComponentByName('critical')
        if critical:
            critical = True
        else:
            critical = False

        value = extension.getComponentByName('extnValue')
        eku_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.ExtKeyUsageSyntax())
        option_dotted_strings = []
        for entry in eku_content:
            option_dotted_strings.append(str(entry))
        option_dotted_strings = list(dict.fromkeys(option_dotted_strings))
        option_oids = [x509.ObjectIdentifier(value) for value in option_dotted_strings]

        extended_key_usage_extension = x509.ExtendedKeyUsage(option_oids)
        return {
            CertificateExtensionOid.EXTENDED_KEY_USAGE: (critical, extended_key_usage_extension)
        }

    def _get_authority_key_identifier(self, extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        critical = extension.getComponentByName('critical')
        if critical:
            raise ValueError('The subject key identifier must not be critical.')
        else:
            critical = False

        value = extension.getComponentByName('extnValue')
        aki_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.AuthorityKeyIdentifier())
        value_is_set = False
        if aki_content['keyIdentifier'].isValue:
            # TODO(AlexHx8472): handle keyIdentifier Value
            value_is_set = True
        if aki_content['authorityCertIssuer'].isValue:
            # TODO(AlexHx8472): handle authorityCertIssuer Value
            value_is_set = True
        if aki_content['authorityCertSerialNumber'].isValue:
            # TODO(AlexHx8472): handle authorityCertSerialNumber Value
            value_is_set = True

        if value_is_set is False:
            return {}
        else:
            # TODO(AlexHx8472): Consider if we should add authorityCertIssuer and authorityCertSerialNumber
            return {
                CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER:
                    (critical, x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key())),
            }

    def _set_authority_key_identifier(self) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        return {
            CertificateExtensionOid.AUTHORITY_KEY_IDENTIFIER:
                (False, x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key())),
        }

    @staticmethod
    def _get_subject_key_identifier(extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        critical = extension.getComponentByName('critical')
        if critical:
            raise ValueError('The subject key identifier must not be critical.')
        else:
            critical = False

        value = extension.getComponentByName('extnValue')
        ski_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.SubjectKeyIdentifier())
        if ski_content.asOctets() == b'':
            return {}
        else:
            return {
                CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER:
                    (critical, x509.SubjectKeyIdentifier(ski_content.asOctets()))
            }

    def _set_subject_key_identifier(self) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        return {
            CertificateExtensionOid.SUBJECT_KEY_IDENTIFIER:
                (False, x509.SubjectKeyIdentifier.from_public_key(self._public_key))
        }

    @staticmethod
    def _get_subject_alternative_name(extension) -> dict[CertificateExtensionOid, tuple[bool, x509.ExtensionType]]:
        critical = extension.getComponentByName('critical')
        if critical:
            critical = True
        else:
            critical = False

        value = extension.getComponentByName('extnValue')
        san_content, _ = decoder.decode(value.asOctets(), asn1Spec=rfc2459.SubjectAltName())

        san_crypto_entries = []
        for entry in san_content:
            if entry.getName() == 'rfc822Name':
                email = entry.getComponent().asOctets().decode()
                san_crypto_entries.append(x509.RFC822Name(email))
            if entry.getName() == 'dNSName':
                dns_name = entry.getComponent().asOctets().decode()
                san_crypto_entries.append(x509.DNSName(dns_name))
            if entry.getName() == 'directoryName':

                rdns_sequence = entry.getComponent().getComponent()
                rdns = []
                for rdn in rdns_sequence:
                    rdn_set = []
                    for attribute_type_and_value in rdn:
                        oid = str(attribute_type_and_value.getComponentByName('type'))
                        value = attribute_type_and_value.getComponentByName('value')
                        decoded_value, _ = decoder.decode(value)
                        if oid != x509.NameOID.X500_UNIQUE_IDENTIFIER.dotted_string:
                            decoded_value = str(decoded_value)
                        name_attr = x509.NameAttribute(x509.ObjectIdentifier(oid), decoded_value)
                        rdn_set.append(name_attr)
                    if rdn_set:
                        rdns.append(x509.RelativeDistinguishedName(rdn_set))
                san_crypto_entries.append(x509.DirectoryName(x509.Name(rdns)))

            if entry.getName() == 'uniformResourceIdentifier':
                uri = entry.getComponent().asOctets().decode()
                san_crypto_entries.append(x509.UniformResourceIdentifier(uri))
            if entry.getName() == 'iPAddress':
                ip_address = ipaddress.ip_address(entry.getComponent().asOctets())
                san_crypto_entries.append(x509.IPAddress(ip_address))
            if entry.getName() == 'otherName':
                other_name = entry.getComponent()
                oid = x509.ObjectIdentifier(str(other_name['type-id']))
                value = other_name['value'].asOctets()
                san_crypto_entries.append(x509.OtherName(oid, value))


        if san_crypto_entries:
            return {
                CertificateExtensionOid.SUBJECT_ALTERNATIVE_NAME:
                    (critical, x509.SubjectAlternativeName(san_crypto_entries))
            }
        return {}



    @staticmethod
    def _prepare_san(extensions):
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
        public_key = load_der_public_key(public_key_der)

        self._public_key = public_key

        return public_key

    @staticmethod
    def _generate_signed_certificate(
            subject_name,
            public_key,
            ca_cert,
            ca_key,
            valid_not_before,
            valid_not_after,
            extensions):
        """
        Generates a signed certificate.

        :param subject_name: The subject's name information.
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
            .not_valid_before(valid_not_before)
            .not_valid_after(valid_not_after)
        )

        for extension_oid, value in extensions.items():
            critical, extension = value
            cert_builder = cert_builder.add_extension(extval=extension, critical=critical)


        # subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(public_key)
        # cert_builder = cert_builder.add_extension(
        #     subject_key_identifier,
        #     critical=False,
        # )
        hash_algorithm = SignatureSuite.get_hash_algorithm_by_key(ca_key)
        cert = cert_builder.sign(ca_key, hash_algorithm)

        def get_template_name(qs):
            for entry in qs:
                if 'tls-server' in entry.value:
                    return TemplateName.TLSSERVER
                if 'tls-client' in entry.value:
                    return TemplateName.TLSCLIENT
                if 'generic' in entry.value:
                    return TemplateName.GENERIC
            return None

        cert_model = CertificateModel.save_certificate(cert)

        qs = cert_model.get_subject_attributes_for_oid(NameOid.PSEUDONYM)
        for attr_value in qs:
            device: DeviceModel = DeviceModel.get_by_name(attr_value.value)
            if device:
                device.save_certificate(
                    certificate=cert_model,
                    certificate_type=CertificateTypes.APPLICATION,
                    domain=device.domain,
                    template_name=get_template_name(qs),
                    protocol='cmp'
                    )
        return cert

    @staticmethod
    def _serialize_client_cert(client_cert: Certificate) -> bytes:
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
