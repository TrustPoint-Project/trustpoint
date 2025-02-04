from __future__ import annotations


import enum

from cryptography import x509
# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from django.utils.translation import gettext_lazy as _
# from pyasn1.codec.der import decoder
# from pyasn1_modules import rfc5280


from typing import TYPE_CHECKING, cast


if TYPE_CHECKING:
    from typing import Union
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


class NameOid(enum.Enum):
    # OID, abbreviation, full_name, verbose_name, is common in certificates

    # ITU
    OBJECT_CLASS = ('2.5.4.0', '', 'objectClass', _('Object Class'), False)
    ALIASED_ENTRY_NAME = ('2.5.4.1', '', 'aliasedEntryName', _('Aliased Entry Name'), False)
    KNOWLEDGE_INFORMATION = ('2.5.4.2', '', 'knowledgeInformation', _('Knowledge Information'), False)
    COMMON_NAME = ('2.5.4.3', 'CN', 'commonName', _('Common Name'), True)
    SURNAME = ('2.5.4.4', 'SN', 'Surname', _('Surname'), True)
    SERIAL_NUMBER = ('2.5.4.5', '', 'serialNumber', _('Serial Number'), True)
    COUNTRY_NAME = ('2.5.4.6', 'C', 'countryName', _('Country Name'), True)
    LOCALITY_NAME = ('2.5.4.7', 'L', 'localityName', _('Locality Name'), True)
    STATE_OR_PROVINCE_NAME = ('2.5.4.8', 'ST', 'stateOrProvinceName', _('State or Province Name'), True)
    STREET_ADDRESS = ('2.5.4.9', '', 'streetAddress', _('Street Address'), True)
    ORGANIZATION_NAME = ('2.5.4.10', 'O', 'organizationName', _('Organization Name'), True)
    ORGANIZATIONAL_UNIT_NAME = ('2.5.4.11', 'OU', 'organizationalUnitName', _('Organizational Unit Name'), True)
    TITLE = ('2.5.4.12', 'T', 'title', _('Title'), True)
    DESCRIPTION = ('2.5.4.13', '', 'description', _('Description'), True)
    SEARCH_GUIDE = ('2.5.4.14', '', 'searchGuide', _('Search Guide'), False)
    BUSINESS_CATEGORY = ('2.5.4.15', '', 'businessCategory', _('Business Category'), True)
    POSTAL_ADDRESS = ('2.5.4.16', '', 'postalAddress', _('Postal Address'), True)
    POSTAL_CODE = ('2.5.4.17', '', 'postalCode', _('Postal Code'), True)
    POST_OFFICE_BOX = ('2.5.4.18', '', 'postOfficeBox', _('Post Office Box'), False)
    PHYSICAL_DELIVERY_OFFICE_NAME = (
        '2.5.4.19',
        '',
        'physicalDeliveryOfficeName',
        _('Physical Delivery Office Name'),
        False,
    )
    TELEPHONE_NUMBER = ('2.5.4.20', '', 'telephoneNumber', _('Telephone Number'), True)
    TELEX_NUMBER = ('2.5.4.21', '', 'telexNumber', _('Telex Number'), False)
    TELEX_TERMINAL_IDENTIFIER = ('2.5.4.22', '', 'telexTerminalIdentifier', _('Telex Terminal Identifier'), False)
    FACSIMILE_TELEPHONE_NUMBER = ('2.5.4.23', '', 'facsimileTelephoneNumber', _('Facsimile Telephone Number'), False)
    X121_Address = ('2.5.4.24', '', 'x121Address', _('X121 Address'), False)
    INTERNATIONAL_ISD_NUMBER = ('2.5.4.25', '', 'internationalISDNumber', _('International ISD Number'), False)
    REGISTERED_ADDRESS = ('2.5.4.26', '', 'registeredAddress', _('Registered Address'), True)
    DESTINATION_INDICATOR = ('2.5.4.27', '', 'destinationIndicator', _('Destination Indicator'), False)
    PREFERRED_DELIVERY_METHOD = ('2.5.4.28', '', 'preferredDeliveryMethod', _('Preferred Delivery Method'), False)
    PRESENTATION_ADDRESS = ('2.5.4.29', '', 'presentationAddress', _('Presentation Address'), True)
    SUPPORTED_APPLICATION_CONTEXT = (
        '2.5.4.30',
        '',
        'supportedApplicationContext',
        _('Supported Application Context'),
        False,
    )
    MEMBER = ('2.5.4.31', '', 'member', _('Member'), False)
    OWNER = ('2.5.4.32', '', 'owner', _('Owner'), False)
    ROLE_OCCUPANT = ('2.5.4.33', '', 'roleOccupant', _('Role Occupant'), False)
    SEE_ALSO = ('2.5.4.34', '', 'seeAlso', _('See Also'), False)
    USER_PASSWORD = ('2.5.4.35', '', 'userPassword', _('User Password'), False)
    USER_CERTIFICATE = ('2.5.4.36', '', 'userCertificate', _('User Certificate'), False)
    CA_Certificate = ('2.5.4.37', '', 'cACertificate', _('CA Certificate'), False)
    AUTHORITY_REVOCATION_LIST = ('2.5.4.38', '', 'authorityRevocationList', _('Authority Revocation List'), False)
    CERTIFICATE_REVOCATION_LIST = ('2.5.4.39', '', 'certificateRevocationList', _('Certificate Revocation List'), False)
    CROSS_CERTIFICATE_PAIR = ('2.5.4.40', '', 'crossCertificatePair', _('Cross Certificate Pair'), False)
    NAME = ('2.5.4.41', '', 'name', _('Name'), True)
    GIVEN_NAME = ('2.5.4.42', 'GN', 'givenName', _('Given name'), True)
    INITIALS = ('2.5.4.43', '', 'initials', _('Initials'), True)
    GENERATION_QUALIFIER = ('2.5.4.44', '', 'generationQualifier', _('Generation Qualifier'), True)
    X500_UNIQUE_IDENTIFIER = ('2.5.4.45', '', 'x500UniqueIdentifier', _('X500 Unique identifier'), True)
    DN_QUALIFIER = ('2.5.4.46', '', 'dnQualifier', _('DN Qualifier'), True)
    ENHANCED_SEARCH_GUIDE = ('2.5.4.47', '', 'enhancedSearchGuide', _('Enhanced Search Guide'), False)
    PROTOCOL_INFORMATION = ('2.5.4.48', '', 'protocolInformation', _('Protocol Information'), False)
    DISTINGUISHED_NAME = ('2.5.4.49', '', 'distinguishedName', _('Distinguished Name'), False)
    UNIQUE_MEMBER = ('2.5.4.50', '', 'uniqueMember', _('Unique Member'), False)
    HOUSE_IDENTIFIER = ('2.5.4.51', '', 'houseIdentifier', _('House Identifier'), False)
    SUPPORTED_ALGORITHMS = ('2.5.4.52', '', 'supportedAlgorithms', _('Supported Algorithms'), False)
    DELTA_REVOCATION_LIST = ('2.5.4.53', '', 'deltaRevocationList', _('Delta Revocation List'), False)
    DMD_NAME = ('2.5.4.54', '', 'dmdName', _('DMD Name'), False)
    CLEARANCE = ('2.5.4.55', '', 'clearance', _('Clearance'), False)
    DEFAULT_DIR_QOP = ('2.5.4.56', '', 'defaultDirQop', _('Default DIR QOP'), False)
    ATTRIBUTE_INTEGRITY_INFO = ('2.5.4.57', '', 'attributeIntegrityInfo', _('Attribute Integrity Info'), False)
    ATTRIBUTE_CERTIFICATE = ('2.5.4.58', '', 'attributeCertificate', _('Attribute Certificate'), False)
    ATTRIBUTE_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.59',
        '',
        'attributeCertificateRevocationList',
        _('Attribute Certificate Revocation List'),
        False,
    )
    CONF_KEY_INFO = ('2.5.4.60', '', 'confKeyInfo', _('Conf Key Info'), False)
    AA_Certificate = ('2.5.4.61', '', 'aACertificate', _('AA Certificate'), False)
    ATTRIBUTE_DESCRIPTOR_CERTIFICATE = (
        '2.5.4.62',
        '',
        'attributeDescriptorCertificate',
        _('Attribute Descriptor Certificate'),
        False,
    )
    ATTRIBUTE_AUTHORITY_REVOCATION_LIST = (
        '2.5.4.63',
        '',
        'attributeAuthorityRevocationList',
        _('Attribute Authority Revocation List'),
        False,
    )
    FAMILY_INFORMATION = ('2.5.4.64', '', 'familyInformation', _('Family Information'), False)
    PSEUDONYM = ('2.5.4.65', '', 'pseudonym', _('Pseudonym'), True)
    COMMUNICATIONS_SERVICE = ('2.5.4.66', '', 'communicationsService', _('Communications Service'), False)
    COMMUNICATIONS_NETWORK = ('2.5.4.67', '', 'communicationsNetwork', _('Communications Network'), False)
    CERTIFICATION_PRACTICE_STMT = (
        '2.5.4.68',
        '',
        'certificationPracticeStmt',
        _('Certification Practice Statement'),
        False,
    )
    CERTIFICATE_POLICY = ('2.5.4.69', '', 'certificatePolicy', _('Certificate Policy'), False)
    PKI_PATH = ('2.5.4.70', '', 'pkiPath', _('PKI Path'), False)
    PRIVILEGE_POLICY = ('2.5.4.71', '', 'privilegePolicy', _('Privilege Policy'), False)
    ROLE = ('2.5.4.72', '', 'role', _('Role'), False)
    PMI_DELEGATION_PATH = ('2.5.4.73', '', 'pmiDelegationPath', _('PMI Delegation Path'), False)
    PROTECTED_PRIVILEGE_POLICY = ('2.5.4.74', '', 'protectedPrivilegePolicy', _('Protected Privilege Policy'), False)
    XML_PRIVILEGE_INFO = ('2.5.4.75', '', 'xMLPrivilegeInfo', _('XML Privilege Info'), False)
    XML_PRIV_POLICY = ('2.5.4.76', '', 'xmlPrivPolicy', _('XML Privilege Policy'), False)
    UUID_PAIR = ('2.5.4.77', '', 'uuidPair', _('UUID Pair'), False)
    TAG_OID = ('2.5.4.78', '', 'tagOid', _('Tag OID'), False)
    UII_FORMAT = ('2.5.4.79', '', 'uiiFormat', _('Unique Item Identifier Format'), False)
    UII_IN_URN = ('2.5.4.80', '', 'uiiInUrn', _('Unique Item Identifier in URN'), False)
    CONTENT_URL = ('2.5.4.81', '', 'contentUrl', _('Content URL'), False)
    PERMISSION = ('2.5.4.82', '', 'permission', _('Permission'), False)
    URI = ('2.5.4.83', '', 'uri', _('Uniform Resource Identifier (URI)'), False)
    PWD_ATTRIBUTE = ('2.5.4.84', '', 'pwdAttribute', _('Password Attribute'), False)
    USER_PWD = ('2.5.4.85', '', 'userPwd', _('User Password'), False)
    URN = ('2.5.4.86', '', 'urn', _('Uniform Resource Name (URN)'), False)
    URL = ('2.5.4.87', '', 'url', _('Uniform Resource Locator (URL)'), False)
    UTM_COORDINATES = ('2.5.4.88', '', 'utmCoordinates', _('UTM (Universal Transverse Mercator) Coordinates'), False)
    URN_C = ('2.5.4.89', '', 'urnC', _('Uniform Resource Locator Component (urnC)'), False)
    UII = ('2.5.4.90', '', 'uii', _('Unique Item Identifier (UII)'), False)
    EPC = ('2.5.4.91', '', 'epc', _('Electronic Product Code'), False)
    TAG_AFI = ('2.5.4.92', '', 'tagAfi', _('Tag Application Family Identifier (Tag AFI)'), False)
    EPC_FORMAT = ('2.5.4.93', '', 'epcFormat', _('Electronic Product Code Format'), False)
    EPC_IN_URN = ('2.5.4.94', '', 'epcInUrn', _('Electronic Product Code in URN'), False)
    LDAP_URL = ('2.5.4.95', '', 'ldapUrl', _('LDAP URL'), False)
    TAG_LOCATION = ('2.5.4.96', '', 'tagLocation', _('Tag Location'), False)
    ORGANIZATION_IDENTIFIER = ('2.5.4.97', '', 'organizationIdentifier', _('Organization Identifier'), True)
    COUNTRY_CODE_3C = ('2.5.4.98', '', 'countryCode3c', _('Country Code 3C (ISO 3166-1 alpha-3)'), False)
    COUNTRY_CODE_3N = ('2.5.4.99', '', 'countryCode3n', _('Country Code 3N ( ISO 3166-1 numeric-3)'), False)
    DNS_NAME = ('2.5.4.100', '', 'dnsName', _('DNS Name'), False)
    EE_PK_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.101',
        '',
        'eepkCertificateRevocationList',
        _('End-Entity Public-Key Certificate Revocation List'),
        False,
    )
    EE_ATTR_CERTIFICATE_REVOCATION_LIST = (
        '2.5.4.102',
        '',
        'eeAttrCertificateRevocationList',
        _('End-Entity Attribute Certificate Revocation List'),
        False,
    )
    SUPPORTED_PUBLIC_KEY_ALGORITHMS = (
        '2.5.4.103',
        '',
        'supportedPublicKeyAlgorithms',
        _('Supported Public-Key Algorithms'),
        False,
    )
    INT_EMAIL = ('2.5.4.104', '', 'intEmail', _('Internationalized Email Address'), False)
    JID = ('2.5.4.105', '', 'jid', _('Jabber Identifier'), False)
    OBJECT_IDENTIFIER = ('2.5.4.106', '', 'objectIdentifier', _('Object Identifier'), False)

    # GOST Algorithms, RFC 9215, Russian, Broken Cypher!
    OGRN = ('1.2.643.100.1', '', 'ogrn', _('Main State Registration Number of juridical entities (OGRN)'), False)
    SNILS = ('1.2.643.100.3', '', 'snils', _('Individual Insurance Account Number (SNILS)'), False)
    INNLE = ('1.2.643.100.4', '', 'innle', _('Individual Taxpayer Number (ITN) of the legal entity'), False)
    OGRN_IP = ('1.2.643.100.5', '', 'ogrnip', _('Main State Registration Number of individual entrepreneurs'), False)
    IDENTIFICATION_KIND = ('1.2.643.100.114', '', 'identificationKind', _('Identification Kind'), False)
    INN = ('1.2.643.3.131.1.1', '', 'inn', _('Individual Taxpayer Number (ITN, INN)'), False)

    # RFC 2985
    # emailAddress is deprecated, use altName extension
    EMAIL_ADDRESS = ('1.2.840.113549.1.9.1', 'E', 'emailAddress', _('Email Address (Deprecated)'), False)
    UNSTRUCTURED_NAME = ('1.2.840.113549.1.9.2', '', 'unstructuredName', _('Unstructured Name (FQDN)'), True)
    CONTENT_TYPE = ('1.2.840.113549.1.9.3', '', 'contentType', _('Content Type'), False)
    UNSTRUCTURED_ADDRESS = ('1.2.840.113549.1.9.8', '', 'unstructuredAddress', _('Unstructured Address'), True)

    # RFC 3039, RFC 2247, RFC 4519, RFC 5912
    UID = ('0.9.2342.19200300.100.1.1', 'UID', 'uid', _('User ID (UID)'), True)
    DOMAIN_COMPONENT = ('0.9.2342.19200300.100.1.25', 'DC', 'domainComponent', _('Domain Component'), True)

    JURISDICTION_OF_INCORPORATION_LOCALITY_NAME = (
        '1.3.6.1.4.1.311.60.2.1.1',
        '',
        'jurisdictionOfIncorporationLocalityName',
        _('Jurisdiction Of Incorporation Locality Name'),
        False,
    )
    JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME = (
        '1.3.6.1.4.1.311.60.2.1.2',
        '',
        'jurisdictionOfIncorporationStateOrProvinceName',
        _('Jurisdiction Of Incorporation State Or Province Name'),
        False,
    )
    jurisdiction_Of_Incorporation_Country_Name = (
        '1.3.6.1.4.1.311.60.2.1.3',
        '',
        'jurisdictionOfIncorporationCountryName',
        _('Jurisdiction Of Incorporation Country Name'),
        False,
    )

    # Spain related
    DNI = ('1.3.6.1.4.1.19126.3', '', 'dni', _('DNI - National identity document (Spain)'), False)
    NSS = ('1.3.6.1.4.1.19126.4', '', 'nss', _('NSS - Social Security Number (Spain)'), False)
    CIRCULATION_PERMIT_NUMBER = (
        '1.3.6.1.4.1.19126.5',
        '',
        'circulationPermitNumber',
        _('Circulation Permit Number (SPAIN)'),
        False,
    )
    CIF = ('1.3.6.1.4.1.19126.21', '', 'cif', _('CIF - Tax Identification Code (Spain)'), False)
    NIF = ('2.16.724.4.307', '', 'nif', _('NIF - Number of fiscal identification (Spain)'), False)

    def __new__(
        cls: type(NameOid), dotted_string: str, abbreviation: str, full_name: str, verbose_name: str, common: bool
    ) -> object:
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.abbreviation = abbreviation
        obj.full_name = full_name
        obj.verbose_name = verbose_name
        return obj


class CertificateExtensionOid(enum.Enum):
    SUBJECT_DIRECTORY_ATTRIBUTES = ('2.5.29.9', _('Subject Directory Attributes'))
    SUBJECT_KEY_IDENTIFIER = ('2.5.29.14', _('Subject Key Identifier'))
    KEY_USAGE = ('2.5.29.15', _('Key Usage'))
    SUBJECT_ALTERNATIVE_NAME = ('2.5.29.17', _('Subject Alternative Name'))
    ISSUER_ALTERNATIVE_NAME = ('2.5.29.18', _('Issuer Alternative Name'))
    BASIC_CONSTRAINTS = ('2.5.29.19', _('Basic Constraints'))
    NAME_CONSTRAINTS = ('2.5.29.30', _('Name Constraints'))
    CRL_DISTRIBUTION_POINTS = ('2.5.29.31', _('Crl Distribution Points'))
    CERTIFICATE_POLICIES = ('2.5.29.32', _('Certificate Policies'))
    POLICY_MAPPINGS = ('2.5.29.33', _('Policy Mappings'))
    AUTHORITY_KEY_IDENTIFIER = ('2.5.29.35', _('Authority Key Identifier'))
    POLICY_CONSTRAINTS = ('2.5.29.36', _('Policy Constraints'))
    EXTENDED_KEY_USAGE = ('2.5.29.37', _('Extended Key Usage'))
    FRESHEST_CRL = ('2.5.29.46', _('Freshest CRL'))
    INHIBIT_ANY_POLICY = ('2.5.29.54', _('Inhibit Any Policy'))
    ISSUING_DISTRIBUTION_POINT = ('2.5.29.28', _('Issuing Distribution Point'))
    AUTHORITY_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.1', _('Authority Information Access'))
    SUBJECT_INFORMATION_ACCESS = ('1.3.6.1.5.5.7.1.11', _('Subject Information Access'))
    OCSP_NO_CHECK = ('1.3.6.1.5.5.7.48.1.5', _('OCSP No Check'))
    TLS_FEATURE = ('1.3.6.1.5.5.7.1.24', _('TLS Feature'))
    CRL_NUMBER = ('2.5.29.20', _('CRL Number'))
    DELTA_CRL_INDICATOR = ('2.5.29.27', _('Delta CRL Indicator'))
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.2', _('Precert Signed Certificate Timestamps'))
    PRECERT_POISON = ('1.3.6.1.4.1.11129.2.4.3', _('Precert Poison'))
    SIGNED_CERTIFICATE_TIMESTAMPS = ('1.3.6.1.4.1.11129.2.4.5', _('Signed Certificate Timestamps'))
    MS_CERTIFICATE_TEMPLATE = ('1.3.6.1.4.1.311.21.7', _('Microsoft Certificate Template'))

    @staticmethod
    def get_short_description_str() -> str:
        return _('Extension OID')

    def __new__(cls, dotted_string, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj


class NamedCurve(enum.Enum):
    # OID, verbose_name, key_size

    NONE = ('None', '', 0)
    SECP192R1 = ('1.2.840.10045.3.1.1', _('SECP192R1'), 192)
    SECP224R1 = ('1.3.132.0.33', _('SECP224R1'), 224)
    SECP256K1 = ('1.3.132.0.10', _('SECP256K1'), 256)
    SECP256R1 = ('1.2.840.10045.3.1.7', _('SECP256R1'), 256)
    SECP384R1 = ('1.3.132.0.34', _('SECP384R1'), 384)
    SECP521R1 = ('1.3.132.0.35', _('SECP521R1'), 521)
    BRAINPOOLP256R1 = ('1.3.36.3.3.2.8.1.1.7', _('BRAINPOOLP256R1'), 256)
    BRAINPOOLP384R1 = ('1.3.36.3.3.2.8.1.1.11', _('BRAINPOOLP384R1'), 384)
    BRAINPOOLP512R1 = ('1.3.36.3.3.2.8.1.1.13', _('BRAINPOOLP512R1'), 512)
    SECT163K1 = ('1.3.132.0.1', _('SECT163K1'), 163)
    SECT163R2 = ('1.3.132.0.15', _('SECT163R2'), 163)
    SECT233K1 = ('1.3.132.0.26', _('SECT233K1'), 233)
    SECT233R1 = ('1.3.132.0.27', _('SECT233R1'), 233)
    SECT283K1 = ('1.3.132.0.16', _('SECT283K1'), 283)
    SECT283R1 = ('1.3.132.0.17', _('SECT283R1'), 283)
    SECT409K1 = ('1.3.132.0.36', _('SECT409K1'), 409)
    SECT409R1 = ('1.3.132.0.37', _('SECT409R1'), 409)
    SECT571K1 = ('1.3.132.0.38', _('SECT571K1'), 571)
    SECT571R1 = ('1.3.132.0.39', _('SECT571R1'), 570)

    def __new__(cls, dotted_string, verbose_name, key_size):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.key_size = key_size
        return obj


class RsaPaddingScheme(enum.Enum):
    NONE = 'None'
    PKCS1v15 = 'PKCS#1 v1.5'
    PSS = 'PSS'

    def __new__(cls, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = verbose_name
        obj.verbose_name = verbose_name
        return obj


class PublicKeyAlgorithmOid(enum.Enum):
    NONE = ('NONE', _('None'))
    ECC = ('1.2.840.10045.2.1', _('ECC'))
    RSA = ('1.2.840.113549.1.1.1', _('RSA'))

    # TODO(AlexHx8472): Support ED25519, ED448
    # ED25519 = ('1.3.101.112', _('ED25519'))
    # ED448 = ('1.3.101.113', _('ED448'))

    def __new__(cls, dotted_string, verbose_name):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        return obj

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyAlgorithmOid:
        return cls.from_public_key(certificate.public_key())

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyAlgorithmOid:
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyAlgorithmOid:
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls.RSA
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls.ECC
        err_msg = 'Unsupported key type, expected RSA or ECC key.'
        raise TypeError(err_msg)


class AlgorithmIdentifier(enum.Enum):
    # OID, verbose_name, public_key_algorithm_oid, padding_scheme

    RSA_MD5 = ('1.2.840.113549.1.1.4', _('RSA with MD5'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA1 = ('1.2.840.113549.1.1.5', _('RSA with SHA1'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA1_ALT = ('1.3.14.3.2.29', _('RSA with SHA1'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA224 = ('1.3.14.3.2.29', _('RSA with SHA224'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA256 = ('1.2.840.113549.1.1.11', _('RSA with SHA256'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA384 = ('1.2.840.113549.1.1.12', _('RSA with SHA384'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA512 = ('1.2.840.113549.1.1.13', _('RSA with SHA512'), PublicKeyAlgorithmOid.RSA, RsaPaddingScheme.PKCS1v15)
    RSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.13',
        _('RSA with SHA3-224'),
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
    )
    RSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.14',
        _('RSA with SHA3-256'),
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
    )
    RSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.15',
        _('RSA with SHA3-384'),
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
    )
    RSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.16',
        _('RSA with SHA3-512'),
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
    )

    # TODO(AlexHx8472): Add support for RSA PSS padding.
    # RSASSA_PSS = (
    #     '1.2.840.113549.1.1.10',
    #     _('RSA (RSASSA-PSS), Padding: PSS'),
    #     PublicKeyAlgorithmOid.RSA,
    #     RsaPaddingScheme.PSS,
    # )

    ECDSA_SHA1 = ('1.2.840.10045.4.1', _('ECDSA with SHA1'), PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA224 = ('1.2.840.10045.4.3.1', _('ECDSA with SHA224'), PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA256 = ('1.2.840.10045.4.3.2', _('ECDSA with SHA256'), PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA384 = ('1.2.840.10045.4.3.3', _('ECDSA with SHA384'), PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA512 = ('1.2.840.10045.4.3.4', _('ECDSA with SHA512'), PublicKeyAlgorithmOid.ECC, RsaPaddingScheme.NONE)
    ECDSA_SHA3_224 = (
        '2.16.840.1.101.3.4.3.9',
        _('ECDSA with SHA3-224'),
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
    )
    ECDSA_SHA3_256 = (
        '2.16.840.1.101.3.4.3.10',
        _('ECDSA with SHA3-256'),
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
    )
    ECDSA_SHA3_384 = (
        '2.16.840.1.101.3.4.3.11',
        _('ECDSA with SHA3-384'),
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
    )
    ECDSA_SHA3_512 = (
        '2.16.840.1.101.3.4.3.12',
        _('ECDSA with SHA3-512'),
        PublicKeyAlgorithmOid.ECC,
        RsaPaddingScheme.NONE,
    )
    PASSWORD_BASED_MAC = (
        '1.2.840.113533.7.66.13',
        _('Password Based MAC'),
        PublicKeyAlgorithmOid.NONE,
        RsaPaddingScheme.NONE
    )

    def __new__(cls, dotted_string, verbose_name, public_key_algo_oid, padding_scheme):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.public_key_algo_oid = public_key_algo_oid
        obj.padding_scheme = padding_scheme
        return obj

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> AlgorithmIdentifier:
        return cls(certificate.signature_algorithm_oid.dotted_string)

class PublicKeyInfo:

    _public_key_algorithm_oid: PublicKeyAlgorithmOid
    _key_size: int
    _named_curve: None | NamedCurve = None

    def __init__(
            self,
            public_key_algorithm_oid: PublicKeyAlgorithmOid,
            key_size: int,
            named_curve: None | NamedCurve = None
    ) -> None:
        self._public_key_algorithm_oid = public_key_algorithm_oid
        self._key_size = key_size
        print(key_size)
        if self._public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            if self._key_size < 2048:
                err_msg = 'RSA key size must at least be 2048 bits.'
                raise ValueError(err_msg)
            if named_curve is not None:
                err_msg = 'RSA keys cannot have a named curve associated with it.'
                raise ValueError(err_msg)
        elif self._public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if self._key_size < 128:
                err_msg = 'ECC key size must at least be 128 bits.'
                raise ValueError(err_msg)
            if named_curve is None:
                err_msg = 'ECC key must have a named curve associated with it.'
                raise ValueError(err_msg)
            self._named_curve = named_curve

    def __eq__(self, other: PublicKeyInfo) -> bool:
        if self.public_key_algorithm_oid != other.public_key_algorithm_oid:
            return False
        if self.key_size != other.key_size:
            return False
        if self.named_curve != other.named_curve:
            return False
        return True

    @property
    def public_key_algorithm_oid(self) -> PublicKeyAlgorithmOid:
        return self._public_key_algorithm_oid

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def named_curve(self) -> NamedCurve:
        return self._named_curve

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyInfo:
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=public_key.key_size)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
                key_size=public_key.key_size,
                named_curve=cast(NamedCurve, NamedCurve[public_key.curve.name.upper()]),
            )
        err_msg = 'Unsupported public key type found. Must be RSA or ECC key.'
        raise TypeError(err_msg)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyInfo:
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyInfo:
        return cls.from_public_key(certificate.public_key())


class SignatureSuite:

    _public_key_info: PublicKeyInfo
    _algorithm_identifier: AlgorithmIdentifier

    def __init__(
            self,
            algorithm_identifier: AlgorithmIdentifier,
            public_key_info: PublicKeyInfo):
        self._algorithm_identifier = algorithm_identifier
        self._public_key_info = public_key_info

        self._validate_consistency()

    def __eq__(self, other: SignatureSuite) -> bool:
        if self.public_key_info != other.public_key_info:
            return False
        if self.algorithm_identifier != other.algorithm_identifier:
            return False
        return True

    def _validate_consistency(self) -> None:
        if self.algorithm_identifier.public_key_algo_oid != self.public_key_info.public_key_algorithm_oid:
            err_msg = (
                f'Signature algorithm uses {self.algorithm_identifier.public_key_algo_oid.name}, '
                f'but the public key is a {self.public_key_info.public_key_algorithm_oid.name} key.')
            raise ValueError(err_msg)

    @property
    def algorithm_identifier(self) -> AlgorithmIdentifier:
        return self._algorithm_identifier

    @property
    def public_key_info(self) -> PublicKeyInfo:
        return self._public_key_info

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> SignatureSuite:
        return cls(
            algorithm_identifier=AlgorithmIdentifier.from_certificate(certificate),
            public_key_info=PublicKeyInfo.from_certificate(certificate)
        )

    def public_key_matches_signature_suite(self, public_key: PublicKey) -> bool:
        public_key_info = PublicKeyInfo.from_public_key(public_key)
        if self.public_key_info != public_key_info:
            return False
        return True

    def private_key_matches_signature_suite(self, private_key: PrivateKey) -> bool:
        return self.public_key_matches_signature_suite(private_key.public_key())

    def certificate_matches_signature_suite(self, certificate: x509.Certificate) -> bool:
        signature_suite = SignatureSuite.from_certificate(certificate)
        if self != signature_suite:
            return False
        return True


class HashAlgorithm(enum.Enum):
    """Enum of hash algorithms mapped to their OID and cryptography hash implementation."""

    MD5 = ('1.2.840.113549.2.5', _('MD5'), hashes.MD5)

    SHA1 = ('1.3.14.3.2.26', _('SHA1'), hashes.SHA1)

    SHA224 = ('2.16.840.1.101.3.4.2.4', _('SHA224'), hashes.SHA224)
    SHA256 = ('2.16.840.1.101.3.4.2.1', _('SHA256'), hashes.SHA256)
    SHA384 = ('2.16.840.1.101.3.4.2.2', _('SHA384'), hashes.SHA384)
    SHA512 = ('2.16.840.1.101.3.4.2.3', _('SHA512'), hashes.SHA512)

    # SHA-3 family
    SHA3_224 = ('2.16.840.1.101.3.4.2.7', _('SHA3-224'), hashes.SHA3_224)
    SHA3_256 = ('2.16.840.1.101.3.4.2.8', _('SHA3-256'), hashes.SHA3_256)
    SHA3_384 = ('2.16.840.1.101.3.4.2.9', _('SHA3-384'), hashes.SHA3_384)
    SHA3_512 = ('2.16.840.1.101.3.4.2.10', _('SHA3-512'), hashes.SHA3_512)

    # SHAKE algorithms
    SHAKE128 = ('2.16.840.1.101.3.4.2.11', _('Shake-128'), hashes.SHAKE128)
    SHAKE256 = ('2.16.840.1.101.3.4.2.12', _('Shake-256'), hashes.SHAKE256)
    
    def __new__(cls, dotted_string, verbose_name: str, hash_algorithm: type[hashes.HashAlgorithm]):
        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.dotted_string = dotted_string
        obj.verbose_name = verbose_name
        obj.hash_algorithm = hash_algorithm
        return obj

    def get_hash_function(self) -> hashes.Hash:
        return hashes.Hash(self.hash_algorithm())


class HmacAlgorithm(enum.Enum):

    HMAC_MD5 = ("1.3.6.1.5.5.8.1.1", HashAlgorithm.MD5)

    HMAC_SHA1 = ("1.3.6.1.5.5.8.1.2", HashAlgorithm.SHA1)

    HMAC_SHA224 = ("1.3.6.1.5.5.8.1.4", HashAlgorithm.SHA224)
    HMAC_SHA256 = ("1.3.6.1.5.5.8.1.5", HashAlgorithm.SHA256)
    HMAC_SHA384 = ("1.3.6.1.5.5.8.1.6", HashAlgorithm.SHA384)
    HMAC_SHA512 = ("1.3.6.1.5.5.8.1.7", HashAlgorithm.SHA512)

    HMAC_SHA3_224 = ('2.16.840.1.101.3.4.2.13', HashAlgorithm.SHA3_224)
    HMAC_SHA3_256 = ('2.16.840.1.101.3.4.2.14', HashAlgorithm.SHA3_256)
    HMAC_SHA3_384 = ('2.16.840.1.101.3.4.2.15', HashAlgorithm.SHA3_384)
    HMAC_SHA3_512 = ('2.16.840.1.101.3.4.2.16', HashAlgorithm.SHA3_512)

    # No HMAC with SHAKE

    def __new__(cls, dotted_string, hash_algorithm: HashAlgorithm):

        obj = object.__new__(cls)
        obj._value_ = dotted_string
        obj.hash_algorithm = hash_algorithm
        return obj