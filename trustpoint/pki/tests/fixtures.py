import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone

from pki.models.certificate import CertificateModel
import pytest  # type: ignore  # noqa: PGH003
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    DirectoryName,
    DNSName,
    ExtendedKeyUsage,
    IPAddress,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    NoticeReference,
    OtherName,
    PolicyInformation,
    RegisteredID,
    RFC822Name,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
    UserNotice,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pyasn1.codec.der.encoder import encode  # type: ignore  # noqa: PGH003
from pyasn1.type import char  # type: ignore  # noqa: PGH003

from pki.tests import (
    COMMON_NAME,
    COUNTRY_NAME,
    DNS_NAME_VALUE,
    IP_ADDRESS_VALUE,
    KEY_USAGE_FLAGS,
    ORGANIZATION_NAME,
    OTHER_NAME_CONTENT,
    OTHER_NAME_OID,
    REGISTERED_ID_OID,
    RFC822_EMAIL,
    URI_VALUE,
)

# ----------------------------
# RSA Private Key Fixture
# ----------------------------

@pytest.fixture(scope="function")
def rsa_private_key() -> rsa.RSAPrivateKey:
    """
    Generate a reusable RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# ----------------------------
# EC Private Key Fixture
# ----------------------------

@pytest.fixture(scope="function")
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """
    Generate a reusable EC private key.
    """
    return ec.generate_private_key(ec.SECP256R1())

# ----------------------------
# Basic Self-Signed Certificate Fixture
# ----------------------------

@pytest.mark.django_db
@pytest.fixture(scope="function")
def self_signed_cert_basic(rsa_private_key) -> CertificateModel:
    """Creates a self-signed CA certificate with minimal extensions and saves it to the database once per module.

    We manually unblock the DB because this fixture has 'module' scope.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    ])
    issuer = subject
    now = datetime.now(timezone.utc)

    basic_constraints = BasicConstraints(ca=True, path_length=None)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(basic_constraints, critical=True)
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )

    cert_model = CertificateModel.save_certificate(cert)
    return (cert_model, cert)

# ----------------------------
# Self-Signed Certificate with Extensions Fixture
# ----------------------------

@pytest.fixture(scope="function")
def self_signed_cert_with_ext(rsa_private_key) -> x509.Certificate:
    """Create a self-signed certificate with multiple extensions."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    ])
    issuer = subject
    now = datetime.now(timezone.utc)

    # Build General Names
    rfc822_name = RFC822Name(RFC822_EMAIL)
    dns_name = DNSName(DNS_NAME_VALUE)
    uri = UniformResourceIdentifier(URI_VALUE)
    directory_name = DirectoryName(
        x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME)])
    )
    registered_id = RegisteredID(ObjectIdentifier(REGISTERED_ID_OID))
    ip_addr = IPAddress(ipaddress.ip_address(IP_ADDRESS_VALUE))

    other_name_content = char.UTF8String(OTHER_NAME_CONTENT)
    other_name_der = encode(other_name_content)
    other_name = OtherName(
        type_id=ObjectIdentifier(OTHER_NAME_OID),
        value=other_name_der
    )

    serial_number = x509.random_serial_number()

    san = SubjectAlternativeName([
        rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name
    ])
    ian = IssuerAlternativeName([
        rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name
    ])

    key_usage = KeyUsage(**KEY_USAGE_FLAGS)

    public_key = rsa_private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_identifier = hashlib.sha1(public_key_bytes).digest()

    aki = AuthorityKeyIdentifier(
        key_identifier=key_identifier,
        authority_cert_issuer=[rfc822_name, dns_name, uri, directory_name, registered_id, ip_addr, other_name],
        authority_cert_serial_number=serial_number
    )
    ski = SubjectKeyIdentifier(digest=key_identifier)

    cp = x509.CertificatePolicies([
        PolicyInformation(
            policy_identifier=ObjectIdentifier("2.23.140.1.1"),
            policy_qualifiers=[
                "https://example-ev-certs.com/cps",
                UserNotice(
                    notice_reference=NoticeReference(
                        organization="Example EV Certification Authority",
                        notice_numbers=[1, 2]
                    ),
                    explicit_text="EV certificates issued under Example EV CA's CP/CPS."
                ),
            ],
        ),
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("2.23.140.1.2.1"),
            policy_qualifiers=[
                'https://example-dv-certs.com/cps',
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text='DV certificates issued with minimal identity validation.'
                )
            ]
        )
    ])

    eku = ExtendedKeyUsage([
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.CODE_SIGNING,
        ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ExtendedKeyUsageOID.TIME_STAMPING,
        ExtendedKeyUsageOID.OCSP_SIGNING,
    ])

    name_constraints = NameConstraints(
        permitted_subtrees=[rfc822_name, dns_name, uri],
        excluded_subtrees=[directory_name, registered_id, other_name]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(san, critical=False)
        .add_extension(ian, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(ski, critical=False)
        .add_extension(cp, critical=True)
        .add_extension(eku, critical=False)
        .add_extension(name_constraints, critical=True)
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )
    return cert
