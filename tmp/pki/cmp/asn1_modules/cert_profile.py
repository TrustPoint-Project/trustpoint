from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful, char
from pyasn1_modules import rfc2459, rfc4210, rfc5280, rfc5652

MAX = float('inf')

# Define OIDs
class CertProfileOids:
    """
    This class holds Object Identifiers (OIDs) used in certificate profiles and controls.
    These OIDs are defined as per various RFCs.
    """
    id_it_certReqTemplate = univ.ObjectIdentifier('1.3.6.1.5.5.7.4.19')  # OID for certReqTemplate
    id_regCtrl_algId = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.11')  # OID for id-regCtrl-algId
    id_regCtrl_rsaKeyLen = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.12')  # OID for id-regCtrl-rsaKeyLen
    id_certProfile = univ.ObjectIdentifier('1.3.6.1.5.5.7.4.21') # OID for id-it-certProfile

    OID_REG_TOKEN = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.1')
    OID_AUTHENTICATOR = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.2')
    OID_PKI_PUBLICATION_INFO = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.3')
    OID_PKI_ARCHIVE_OPTIONS = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.4')
    OID_OLD_CERT_ID = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.5')
    OID_PROTOCOL_ENCR_KEY = univ.ObjectIdentifier('1.3.6.1.5.5.7.5.1.6')

    OID_RSA_ENCRYPTION = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
    OID_ECC = univ.ObjectIdentifier('1.2.840.10045.2.1')

    OID_SEC256_R1 = univ.ObjectIdentifier('1.2.840.10045.3.1.7')


# Define the necessary ASN.1 structures

class CertId(univ.Sequence):
    """
    CertId ::= SEQUENCE {
        issuer           GeneralName,
        serialNumber     INTEGER
    }

    CertId is used to uniquely identify a certificate by its issuer and serial number.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', rfc2459.GeneralName()),
        namedtype.NamedType('serialNumber', univ.Integer())
    )


# AttributeTypeAndValue for RDNs and Extensions
class AttributeTypeAndValue(univ.Sequence):
    """
    AttributeTypeAndValue ::= SEQUENCE {
        type               OBJECT IDENTIFIER,
        value              ANY DEFINED BY type
    }

    This class represents an attribute type and its corresponding value.
    It is commonly used in the context of Relative Distinguished Names (RDNs) and certificate extensions.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )

class RegistrationTokenControl(AttributeTypeAndValue):
    """
    Represents the regToken control as defined in RFC 4211, section 6.1.

    A regToken control contains one-time information (e.g., a secret value)
    that the CA uses to verify the identity of the subject before issuing a certificate.
    """
    def __init__(self, reg_token_value):
        self['type'] = CertProfileOids.OID_REG_TOKEN
        self['value'] = char.UTF8String(reg_token_value)

class AuthenticatorControl(AttributeTypeAndValue):
    """
    Represents the authenticator control as defined in RFC 4211, section 6.2.

    An authenticator control contains information used for non-cryptographic identity checks
    in communication with the CA, such as a shared secret or a hash of such information.
    """
    def __init__(self, authenticator_value):
        # Setting the type to the OID for authenticator
        self['type'] = CertProfileOids.OID_AUTHENTICATOR
        # The value is a UTF8String
        self['value'] = char.UTF8String(authenticator_value)

class SinglePubInfo(univ.Sequence):
    """
    Represents a single publication information entry as defined in RFC 4211, section 6.3.

    SinglePubInfo ::= SEQUENCE {
        pubMethod    INTEGER {
            dontCare    (0),
            x500        (1),
            web         (2),
            ldap        (3) },
        pubLocation  GeneralName OPTIONAL
    }

    pubMethod specifies the method by which the certificate should be published,
    and pubLocation optionally specifies the location.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pubMethod', univ.Integer(
            namedValues=namedval.NamedValues(
                ('dontCare', 0),
                ('x500', 1),
                ('web', 2),
                ('ldap', 3)
            )
        )),
        namedtype.OptionalNamedType('pubLocation', rfc2459.GeneralName())
    )

class PKIPublicationInfo(univ.Sequence):
    """
    Represents PKI publication information as defined in RFC 4211, section 6.3.

    PKIPublicationInfo ::= SEQUENCE {
        action     INTEGER {
            dontPublish (0),
            pleasePublish (1) },
        pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL
    }

    This class is used to influence the CA/RA's publication of a certificate.
    The action field specifies whether or not to publish the certificate, and pubInfos
    optionally provides the locations for publication.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('action', univ.Integer(
            namedValues=namedval.NamedValues(
                ('dontPublish', 0),
                ('pleasePublish', 1)
            )
        )),
        namedtype.OptionalNamedType('pubInfos', univ.SequenceOf(componentType=SinglePubInfo()).subtype(
            sizeSpec=constraint.ValueSizeConstraint(1, float('inf'))
        ))
    )

class PublicationInformationControl(AttributeTypeAndValue):
    """
    Represents the pkiPublicationInfo control as defined in RFC 4211, section 6.3.

    This control encapsulates PKIPublicationInfo to advise the CA/RA on how to publish the certificate.
    """
    def __init__(self, publication_info):
        self['type'] = CertProfileOids.OID_PKI_PUBLICATION_INFO
        self['value'] = publication_info

class EncryptedValue(univ.Sequence):
    """
    Represents an encrypted value as defined in RFC 4211, section 6.4.

    EncryptedValue ::= SEQUENCE {
        intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
        symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
        encSymmKey    [2] BIT STRING           OPTIONAL,
        keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
        valueHint     [4] OCTET STRING         OPTIONAL,
        encValue       BIT STRING
    }

    This class represents a deprecated structure for holding encrypted data,
    typically a private key or other sensitive information.
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('intendedAlg', rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('symmAlg', rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('encSymmKey', univ.BitString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('keyAlg', rfc5280.AlgorithmIdentifier().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('valueHint', univ.OctetString().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.NamedType('encValue', univ.BitString())
    )

class EncryptedKey(univ.Choice):
    """
    Represents an encrypted key as defined in RFC 4211, section 6.4.

    EncryptedKey ::= CHOICE {
        encryptedValue        EncryptedValue, -- deprecated
        envelopedData     [0] EnvelopedData }

    This structure can either hold an `EncryptedValue` (deprecated) or `EnvelopedData`,
    which contains the encrypted private key.
    """
    componentType = namedtype.NamedTypes(
        # namedtype.NamedType('encryptedValue', EncryptedValue()), # deprecated
        namedtype.NamedType('envelopedData', rfc5652.EnvelopedData().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )

class KeyGenParameters(univ.OctetString):
    """
    Represents key generation parameters as defined in RFC 4211, section 6.4.

    KeyGenParameters ::= OCTET STRING

    This structure holds parameters that allow a private key to be re-generated.
    """
    pass

class PKIArchiveOptions(univ.Choice):
    """
    Represents PKI archive options as defined in RFC 4211, section 6.4.

    PKIArchiveOptions ::= CHOICE {
        encryptedPrivKey     [0] EncryptedKey,
        keyGenParameters     [1] KeyGenParameters,
        archiveRemGenPrivKey [2] BOOLEAN }

    This class allows subscribers to specify how their private key should be archived by the CA/RA.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptedPrivKey', EncryptedKey().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('keyGenParameters', KeyGenParameters().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('archiveRemGenPrivKey', univ.Boolean().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
    )

class OldCertIDControl(AttributeTypeAndValue):
    """
    Represents the oldCertID control as defined in RFC 4211, section 6.5.

    The OldCertID control specifies the certificate to be updated by the current certification request.
    """
    def __init__(self, issuer, serial_number):
        cert_id = CertId()
        cert_id.setComponentByName('issuer', issuer)
        cert_id.setComponentByName('serialNumber', serial_number)

        self['type'] = CertProfileOids.OID_OLD_CERT_ID
        self['value'] = cert_id

class ProtocolEncryptionKeyControl(AttributeTypeAndValue):
    """
    Represents the protocolEncrKey control as defined in RFC 4211, section 6.6.

    This control specifies a key that the CA is to use for encrypting responses to certification requests.
    """
    def __init__(self, subject_public_key_info):
        self['type'] = CertProfileOids.OID_PROTOCOL_ENCR_KEY
        self['value'] = subject_public_key_info

# RelativeDistinguishedName and RDNSequence for subject/issuer fields
class RelativeDistinguishedName(univ.SetOf):
    """
    Represents a relative distinguished name (RDN), which is a set of
    one or more AttributeTypeAndValue pairs.
    """
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    """
    Represents a sequence of relative distinguished names (RDNs).
    """
    componentType = RelativeDistinguishedName()

class Name(rfc2459.Name):
    """
    Represents a distinguished name (DN) for a subject or issuer,
    which is composed of an RDNSequence.
    """
    pass

# Extension and Extensions for certificate extensions
class Extension(univ.Sequence):
    """
    Represents a single certificate extension, which includes an extension ID,
    a criticality flag, and the extension value.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean(False)),
        namedtype.NamedType('extnValue', univ.OctetString())
    )

class Extensions(univ.SequenceOf):
    """
    Represents a sequence of certificate extensions.
    """
    componentType = Extension()

class OptionalValidity(univ.Sequence):
    """
    Represents the optional validity period of a certificate,
    including notBefore and notAfter times.

    OptionalValidity ::= SEQUENCE {
        notBefore  [0] Time OPTIONAL,
        notAfter   [1] Time OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('notBefore', rfc2459.Time().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('notAfter', rfc2459.Time().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )

class CertTemplate(univ.Sequence):
    """
    Represents a certificate template as defined in RFC 4211.

    CertTemplate ::= SEQUENCE {
        version      [0] Version               OPTIONAL,
        serialNumber [1] INTEGER               OPTIONAL,
        signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
        issuer       [3] Name                  OPTIONAL,
        validity     [4] OptionalValidity      OPTIONAL,
        subject      [5] Name                  OPTIONAL,
        publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
        issuerUID    [7] UniqueIdentifier      OPTIONAL, - deprecated
        subjectUID   [8] UniqueIdentifier      OPTIONAL, - deprecated
        extensions   [9] Extensions            OPTIONAL }

    This structure is used to specify the attributes of a certificate to be issued.
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', rfc2459.Version()),
        namedtype.OptionalNamedType('serialNumber', rfc2459.CertificateSerialNumber()),
        namedtype.OptionalNamedType('signingAlg', rfc2459.AlgorithmIdentifier()),
        namedtype.OptionalNamedType('issuer', Name()),
        namedtype.OptionalNamedType('validity', OptionalValidity()),
        namedtype.OptionalNamedType('subject', Name()),
        namedtype.OptionalNamedType('subjectPublicKeyInfo', rfc2459.SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', rfc2459.UniqueIdentifier()),
        namedtype.OptionalNamedType('subjectUniqueID', rfc2459.UniqueIdentifier()),
        namedtype.OptionalNamedType('extensions', Extensions())
    )

class AlgIdCtrl(rfc2459.AlgorithmIdentifier):
    """
    Represents a control for specifying the algorithm identifier used in a certificate request.
    """
    pass

class RsaKeyLenCtrl(univ.Integer):
    """
    Represents a control for specifying the length of an RSA key in a certificate request.
    """
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(1, MAX)

class Controls(univ.SequenceOf):
    """
    Represents a sequence of controls, each defined as an AttributeTypeAndValue pair.

    Controls ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
    """
    componentType = AttributeTypeAndValue()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, rfc4210.MAX)

class CertReqTemplateContent(univ.Sequence):
    """
    Represents the content of a certificate request template.

    CertReqTemplateContent ::= SEQUENCE {
        certTemplate CertTemplate,
        keySpec Controls OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certTemplate', CertTemplate()),
        namedtype.OptionalNamedType('keySpec', Controls())
    )

class CertProfileValue(univ.SequenceOf):
    """
    CertProfileValue ::= SEQUENCE SIZE (1..MAX) OF UTF8String
    """
    componentType = char.UTF8String()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)
