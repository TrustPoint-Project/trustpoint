import os
import json
from pyasn1.type import univ, namedtype, char, constraint, tag
from pyasn1_modules import rfc2459, rfc4210, rfc5280
from pyasn1.codec.der import encoder
import ipaddress


from pki.pki.cmp.asn1_modules import CertTemplate, AttributeTypeAndValue, RelativeDistinguishedName, RDNSequence, \
    Name, Extension, Extensions, AlgIdCtrl, RsaKeyLenCtrl, Controls, CertReqTemplateContent, CertProfileValue, PKIHeader, CertProfileOids


class CertTemplateLoader:
    oid_to_type_map = {
        # Subject Name OIDs
        '2.5.4.3': char.UTF8String,  # Common Name (CN)
        '2.5.4.6': char.PrintableString,  # Country Name (C)
        '2.5.4.7': char.UTF8String,  # Locality Name (L)
        '2.5.4.8': char.UTF8String,  # State or Province Name (ST)
        '2.5.4.9': char.UTF8String,  # Street Address
        '2.5.4.10': char.UTF8String,  # Organization Name (O)
        '2.5.4.11': char.UTF8String,  # Organizational Unit Name (OU)
        '2.5.4.12': char.UTF8String,  # Title
        '2.5.4.42': char.UTF8String,  # Given Name (GN)
        '2.5.4.43': char.UTF8String,  # Initials
        '2.5.4.4': char.UTF8String,  # Surname (SN)
        '2.5.4.44': char.PrintableString,  # Generation Qualifier
        '2.5.4.5': univ.Integer,  # Serial Number
        '2.5.4.45': char.UTF8String,  # Unique Identifier
        '2.5.4.46': char.UTF8String,  # Distinguished Name Qualifier
        '2.5.4.20': char.PrintableString,  # Telephone Number
        '2.5.4.41': char.UTF8String,  # Name
        '1.2.840.113549.1.9.1': char.IA5String,  # Email Address

        # Subject Alternative Name OIDs (GeneralName types)
        '2.5.29.17': univ.SequenceOf,  # Subject Alternative Name extension (GeneralNames)
        '1.3.6.1.5.5.7.8.1': char.IA5String,  # RFC 822 Name (rfc822Name)
        '2.5.29.17.1': char.IA5String,  # DNS Name (dNSName)
        '2.5.29.17.2': univ.OctetString,  # IP Address (iPAddress)
        '2.5.29.17.3': char.IA5String,  # URI (uniformResourceIdentifier)
        '2.5.29.17.4': char.UTF8String,  # X.400 Address
        '2.5.29.17.5': univ.Sequence,  # Directory Name (directoryName)
        '2.5.29.17.6': char.IA5String,  # EDI Party Name (ediPartyName)
        '2.5.29.17.7': univ.ObjectIdentifier,  # Registered ID (registeredID)
    }
    def __init__(self, templates_folder):
        self.templates_folder = templates_folder

    def load_templates(self):
        certificate_templates = {}
        for filename in os.listdir(self.templates_folder):
            if filename.endswith('.json'):
                file_path = os.path.join(self.templates_folder, filename)
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    cert_template_data = data.get("certificateTemplate", {})
                    certificate_template_name = cert_template_data["certificateTemplateName"]
                    cert_template = self.parse_template(cert_template_data)
                    key_spec = self.create_key_spec(cert_template_data)
                    cert_req_template = self.create_cert_req_template(cert_template, key_spec)

                    certificate_templates[certificate_template_name] = cert_req_template

        return certificate_templates

    def create_key_spec(self, data):

        key_algorithm = data["keyAlgorithm"]['algorithm']
        key_parameter = data["keyAlgorithm"]['parameter']

        key_spec = Controls()

        if univ.ObjectIdentifier(key_algorithm) == CertProfileOids.OID_ECC:
            alg_id_ctrl = AlgIdCtrl()
            alg_id_ctrl.setComponentByName('algorithm', univ.ObjectIdentifier(key_algorithm))
            alg_id_ctrl.setComponentByName('parameters', univ.ObjectIdentifier(key_parameter))

            key_spec.setComponents(
                AttributeTypeAndValue().setComponents(
                    CertProfileOids.id_regCtrl_algId,
                    alg_id_ctrl
                ))
        elif univ.ObjectIdentifier(key_algorithm) == CertProfileOids.OID_RSA_ENCRYPTION:
            key_spec.setComponents(
                AttributeTypeAndValue().setComponents(
                    CertProfileOids.id_regCtrl_rsaKeyLen,
                    RsaKeyLenCtrl(int(key_parameter))
                )
            )
        else:
            raise ValueError("OID in certificate template not supported")

        return key_spec

    def create_cert_req_template(self, cert_template, key_spec):
        cert_req_template_content = CertReqTemplateContent()
        cert_req_template_content.setComponentByName('certTemplate', cert_template)
        cert_req_template_content.setComponentByName('keySpec', key_spec)

        cert_req_template = rfc4210.InfoTypeAndValue()
        cert_req_template.setComponentByName("infoType", CertProfileOids.id_it_certReqTemplate)
        cert_req_template.setComponentByName("infoValue", cert_req_template_content)

        return cert_req_template

    def parse_template(self, data):
        cert_template = rfc2459.TBSCertificate()

        subject_oid = rfc5280.id_at.prettyPrint()
        san_oid = rfc5280.id_ce_subjectAltName.prettyPrint()

        # Subject
        if subject_oid in data:
            subject_name = rfc2459.Name()
            rdn_sequence = rfc2459.RDNSequence()
            for idx, (oid, value) in enumerate(data[subject_oid].items()):

                #if value:
                subject_rdn = rfc2459.RelativeDistinguishedName()
                asn1_type = self.oid_to_type_map.get(oid, char.UTF8String)
                attribute = rfc2459.AttributeTypeAndValue().setComponents(
                    univ.ObjectIdentifier(oid),
                    asn1_type(value)
                )

                subject_rdn.setComponentByPosition(0, attribute)
                rdn_sequence.setComponentByPosition(len(rdn_sequence), subject_rdn)

            subject_name.setComponentByPosition(0, rdn_sequence)
            cert_template.setComponentByName('subject', subject_name)

        # Extensions
        if san_oid in data:
            extensions = rfc2459.Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

            general_names = rfc2459.GeneralNames()

            for san_type_name, names in data[san_oid].items():
                for name in names:
                    general_name = rfc2459.GeneralName()

                    if san_type_name == 'dNSName':
                        dns_name = char.IA5String(name).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
                        general_name.setComponentByName('dNSName', dns_name)

                    elif san_type_name == 'iPAddress':
                        if not name:
                            ip_bytes = b''
                        else:
                            ip = ipaddress.ip_address(name)
                            ip_bytes = ip.packed
                        ip_address = univ.OctetString(ip_bytes).subtype(
                            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
                        general_name.setComponentByName('iPAddress', ip_address)

                    elif san_type_name == 'rfc822Name':
                        rfc822_name = char.IA5String(name).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
                        general_name.setComponentByName('rfc822Name', rfc822_name)

                    elif san_type_name == 'uniformResourceIdentifier':
                        uri = char.IA5String(name).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
                        general_name.setComponentByName('uniformResourceIdentifier', uri)

                    else:
                        raise ValueError("SAN type not supported")

                    general_names.append(general_name)

            encoded_general_names = encoder.encode(general_names)

            extension = rfc2459.Extension()
            extension.setComponentByName('extnID', rfc5280.id_ce_subjectAltName)
            extension.setComponentByName('critical', univ.Boolean(False))
            extension.setComponentByName('extnValue', univ.OctetString(encoded_general_names))

            extensions.append(extension)

            print(extensions)

            cert_template.setComponentByName('extensions', extensions)

        if False:
            # signingAlgorithm is deprecated
            signing_algorithm = data["signingAlgorithm"]['algorithm']

            algorithm_identifier = rfc2459.AlgorithmIdentifier()
            algorithm_identifier.setComponentByName('algorithm', signing_algorithm)
            cert_template.setComponentByName('signingAlg', algorithm_identifier)


        return cert_template


# Example usage:
template_loader = CertTemplateLoader('.')
templates = template_loader.load_templates()

