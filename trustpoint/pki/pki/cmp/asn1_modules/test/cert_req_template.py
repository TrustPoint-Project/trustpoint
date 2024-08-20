from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful, char
from pyasn1_modules import rfc2459, rfc4210, rfc5280
from pki.pki.cmp.asn1_modules import CertTemplate, AttributeTypeAndValue, RelativeDistinguishedName, RDNSequence, \
    Name, Extension, Extensions, AlgIdCtrl, RsaKeyLenCtrl, Controls, CertReqTemplateContent, CertProfileValue, PKIHeader, CertProfileOids
from pyasn1.codec.der.encoder import encode as der_encode


def create_cert_template(cn):
    cert_template = CertTemplate()

    # Example subject with RDNs
    subject_name = Name()
    subject_rdn = RelativeDistinguishedName()
    subject_rdn.setComponentByPosition(0, AttributeTypeAndValue().setComponents(
        univ.ObjectIdentifier('2.5.4.3'),  # OID for commonName
        char.UTF8String(cn)
    ))
    subject_name.setComponentByPosition(0, RDNSequence().setComponents(subject_rdn))

    # Adding subject to the certTemplate
    cert_template.setComponentByName('subject', subject_name)

    # Example Extensions
    extensions = Extensions()
    subject_alt_name_ext = Extension()
    subject_alt_name_ext.setComponents(
        univ.ObjectIdentifier('2.5.29.17'),  # OID for subjectAltName
        univ.Boolean(False),  # Criticality
        univ.OctetString()  # SubjectAltName value (should be ASN.1 encoded)
    )
    extensions.setComponentByPosition(0, subject_alt_name_ext)

    # Adding extensions to the certTemplate
    cert_template.setComponentByName('extensions', extensions)

    return cert_template


def create_key_spec():
    alg_id_ctrl = AlgIdCtrl()
    alg_id_ctrl.setComponentByName('algorithm', univ.ObjectIdentifier('1.2.840.10045.2.1'))  # ecPublicKey OID
    alg_id_ctrl.setComponentByName('parameters', univ.ObjectIdentifier('1.2.840.10045.3.1.7'))  # secp256r1 OID

    # Example Key Specification
    key_spec = Controls()
    key_spec.setComponents(
        AttributeTypeAndValue().setComponents(
            CertProfileOids.id_regCtrl_algId,
            alg_id_ctrl
        ),
        AttributeTypeAndValue().setComponents(
            CertProfileOids.id_regCtrl_rsaKeyLen,
            RsaKeyLenCtrl(2048)
        )
    )

    return key_spec


class InfoValue(univ.SequenceOf):
    """
    Represents a control for specifying the length of an RSA key in a certificate request.
    """
    componentType = char.UTF8String
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, rfc4210.MAX)


def create_pki_header():
    sender, recipient = create_sender_recipient()

    profile_seq = univ.SequenceOf(componentType=char.UTF8String())
    profile_seq.append(char.UTF8String("exampleProfile"))

    info_type_and_value = rfc4210.InfoTypeAndValue().subtype(
                                            sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX)
                                        )
    info_type_and_value.setComponentByName('infoType', CertProfileOids.id_certProfile)  # Set the infoType
    info_type_and_value.setComponentByName('infoValue', profile_seq)

    general_info = univ.SequenceOf(componentType=rfc4210.InfoTypeAndValue().subtype(
                                            sizeSpec=constraint.ValueSizeConstraint(1, rfc4210.MAX)
                                        )
                                    ).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))

    general_info.append(info_type_and_value)

    # Create the PKIHeader with a certProfile
    pki_header = PKIHeader()
    pki_header.setComponentByName('pvno', 2)
    pki_header.setComponentByName('sender', sender)
    pki_header.setComponentByName('recipient', recipient)
    pki_header.setComponentByName('generalInfo', general_info)

    return pki_header


def create_sender_recipient():
    sender = rfc2459.GeneralName()
    recipient = rfc2459.GeneralName()

    directory_name = rfc2459.Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))
    rdn_sequence = rfc2459.RDNSequence()
    rdn = rfc2459.RelativeDistinguishedName()
    atv = rfc2459.AttributeTypeAndValue().setComponentByName('type', rfc2459.id_at_commonName)
    atv.setComponentByName('value', char.PrintableString("TEST"))
    rdn.setComponentByPosition(0, atv)
    rdn_sequence.setComponentByPosition(0, rdn)

    directory_name.setComponentByPosition(0, rdn_sequence)

    sender.setComponentByName('directoryName', directory_name)
    recipient.setComponentByName('directoryName', directory_name)

    return sender, recipient


def create_cert_req_template(cert_template, key_spec):
    cert_req_template_content = CertReqTemplateContent()
    cert_req_template_content.setComponentByName('certTemplate', cert_template)
    cert_req_template_content.setComponentByName('keySpec', key_spec)

    cert_req_template = rfc4210.InfoTypeAndValue()
    cert_req_template.setComponentByName("infoType", CertProfileOids.id_it_certReqTemplate)
    cert_req_template.setComponentByName("infoValue", cert_req_template_content)

    return cert_req_template


def create_pki_body(cert_req_template):
    # Create a GenRepContent and add all certReqTemplates
    gen_msg_request = rfc4210.GenRepContent().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 22)
    )

    gen_msg_request.setComponentByPosition(0, cert_req_template)

    pki_body = rfc4210.PKIBody()
    pki_body.setComponentByName("gen", gen_msg_request)

    return pki_body


def create_pki_message():
    cert_template = create_cert_template("TestCn")
    key_spec = create_key_spec()

    # Create multiple cert_req_templates
    cert_req_template = create_cert_req_template(cert_template, key_spec)


    pki_header = create_pki_header()
    pki_body = create_pki_body(cert_req_template)

    pki_message = rfc4210.PKIMessage()
    pki_message.setComponentByName('header', pki_header)
    pki_message.setComponentByName('body', pki_body)

    return pki_message


def main():
    pki_message = create_pki_message()
    print(pki_message)
    encoded_message = der_encode(pki_message)
    print(encoded_message)


if __name__ == "__main__":
    main()
