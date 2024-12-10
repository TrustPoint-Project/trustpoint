import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone

import pytest
from core.serializer import CertificateSerializer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    DirectoryName,
    DNSName,
    IPAddress,
    IssuerAlternativeName,
    KeyUsage,
    OtherName,
    RegisteredID,
    RFC822Name,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import char

from pki.models.certificate import CertificateModel

# ---------------------------- Certificate properties ----------------------------

# Subject Attributes
COMMON_NAME = 'example common name'
COUNTRY_NAME = 'DE'
ORGANIZATION_NAME = 'Example Org'

# GeneralName
RFC822_EMAIL = 'user@example.com'
DNS_NAME_VALUE = 'example.com'
URI_VALUE = 'http://example.com'
DIRECTORY_NAME_ATTR = {'oid': NameOID.ORGANIZATION_NAME.dotted_string, 'value': ORGANIZATION_NAME}
REGISTERED_ID_OID = '1.2.3.4.5'
IP_ADDRESS_VALUE = '192.168.0.1'
OTHER_NAME_OID = '1.3.6.1.4.1.311.20.2.3'
OTHER_NAME_CONTENT = 'Trustpoint to the top'

# Key Usage
KEY_USAGE_FLAGS = {
    'digital_signature': True,
    'content_commitment': True,
    'key_encipherment': True,
    'data_encipherment': True,
    'key_agreement': True,
    'key_cert_sign': True,
    'crl_sign': True,
    'encipher_only': True,
    'decipher_only': True,
}

# ---------------------------- Fixtures ----------------------------

@pytest.fixture(scope='module')
def rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a private RSA key.

    Returns:
        rsa.RSAPrivateKey: The generated RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

@pytest.fixture(scope='module')
def ec_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a private EC key.

    Returns:
        ec.EllipticCurvePrivateKey: The generated EC private key.
    """
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope='module')
def self_signed_cert_with_ext(rsa_private_key) -> x509.Certificate:
    """Generate a self-signed certificate with various extensions and all key usages set to True.

    Args:
        rsa_private_key (rsa.RSAPrivateKey): The RSA private key fixture.

    Returns:
        x509.Certificate: The generated certificate with all extensions and key usages set to True.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
    ])
    issuer = subject
    now = datetime.now(timezone.utc)

    # General Name entries
    rfc822_name = RFC822Name(RFC822_EMAIL)
    dns_name = DNSName(DNS_NAME_VALUE)
    uri = UniformResourceIdentifier(URI_VALUE)
    directory_name = DirectoryName(
        x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME)])
    )
    registered_id = RegisteredID(ObjectIdentifier(REGISTERED_ID_OID))
    ip_address = IPAddress(ipaddress.ip_address(IP_ADDRESS_VALUE))
    other_name_content = char.UTF8String(OTHER_NAME_CONTENT)
    other_name_der = encode(other_name_content)
    other_name = OtherName(
        type_id=ObjectIdentifier(OTHER_NAME_OID),
        value=other_name_der
    )
    cert_serial_number=x509.random_serial_number()

    san = SubjectAlternativeName([
        rfc822_name,
        dns_name,
        uri,
        directory_name,
        registered_id,
        ip_address,
        other_name
    ])

    # Since it's self-signed, IAN = SAN
    ian = IssuerAlternativeName([
        rfc822_name,
        dns_name,
        uri,
        directory_name,
        registered_id,
        ip_address,
        other_name
    ])

    key_usage = KeyUsage(
        digital_signature=KEY_USAGE_FLAGS['digital_signature'],
        content_commitment=KEY_USAGE_FLAGS['content_commitment'],
        key_encipherment=KEY_USAGE_FLAGS['key_encipherment'],
        data_encipherment=KEY_USAGE_FLAGS['data_encipherment'],
        key_agreement=KEY_USAGE_FLAGS['key_agreement'],
        key_cert_sign=KEY_USAGE_FLAGS['key_cert_sign'],
        crl_sign=KEY_USAGE_FLAGS['crl_sign'],
        encipher_only=KEY_USAGE_FLAGS['encipher_only'],
        decipher_only=KEY_USAGE_FLAGS['decipher_only']
    )

    public_key = rsa_private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_identifier = hashlib.sha1(public_key_bytes).digest()

    aki = AuthorityKeyIdentifier(
        key_identifier=key_identifier,
        authority_cert_issuer=[
            rfc822_name,
            dns_name,
            uri,
            directory_name,
            registered_id,
            ip_address,
            other_name
        ],
        authority_cert_serial_number=cert_serial_number
    )

    ski = SubjectKeyIdentifier(
        digest=key_identifier
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(cert_serial_number)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .add_extension(
            key_usage,
            critical=True
        )
        .add_extension(
            san,
            critical=False
        )
        .add_extension(
            ian,
            critical=False
        )
        .add_extension(
            aki,
            critical=False
        )
        .add_extension(
            ski,
            critical=False
        )
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )
    return cert


# ---------------------------- Tests ----------------------------


@pytest.mark.django_db
def test_save_certificate_with_serializer(self_signed_cert_with_ext) -> None:
    """Test saving a certificate using a CertificateSerializer instead of a raw x509.Certificate.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_pem = self_signed_cert_with_ext.public_bytes(serialization.Encoding.PEM)
    serializer = CertificateSerializer(cert_pem)
    cert_model = CertificateModel.save_certificate(serializer)
    assert cert_model.common_name == COMMON_NAME

@pytest.mark.django_db
def test_save_certificate_method(self_signed_cert_with_ext) -> None:
    """Test that save_certificate method creates and stores a certificate model instance.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The self-signed certificate fixture with extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    assert isinstance(cert_model, CertificateModel)
    db_cert = CertificateModel.objects.get(pk=cert_model.pk)
    assert db_cert == cert_model


@pytest.mark.django_db
def test_self_signed_certificate_values(self_signed_cert_with_ext) -> None:
    """Test all relevant values for a self-signed certificate in the cert_model."""
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    now = datetime.now(timezone.utc)

    assert cert_model.certificate_status == cert_model.CertificateStatus.OK

    assert cert_model.is_self_signed is True

    assert cert_model.common_name == COMMON_NAME

    assert self_signed_cert_with_ext.fingerprint(hashes.SHA256()).hex().upper() == cert_model.sha256_fingerprint

    assert self_signed_cert_with_ext.signature_algorithm_oid.dotted_string == cert_model.signature_algorithm_oid
    # @TODO: signature_algorithm_padding_scheme
    assert self_signed_cert_with_ext.signature.hex().upper() == cert_model.signature_value

    assert cert_model.version == 2

    assert hex(self_signed_cert_with_ext.serial_number)[2:].upper() == cert_model.serial_number

    issuer = []
    for rdn in self_signed_cert_with_ext.issuer.rdns:
        for attr_type_and_value in rdn:
            issuer.append(
                (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
            )

    assert len(issuer) == len(cert_model.issuer.all())

    assert self_signed_cert_with_ext.issuer.public_bytes().hex().upper() == cert_model.issuer_public_bytes

    assert self_signed_cert_with_ext.not_valid_before_utc == cert_model.not_valid_before
    assert self_signed_cert_with_ext.not_valid_after_utc == cert_model.not_valid_after

    subject = []
    for rdn in self_signed_cert_with_ext.subject.rdns:
        for attr_type_and_value in rdn:
            subject.append(
                (attr_type_and_value.oid.dotted_string, attr_type_and_value.value)
            )

    # spki_algorithm_oid, spki_key_size, spki_ec_curve_oid

    assert self_signed_cert_with_ext.public_bytes(encoding=serialization.Encoding.PEM).decode() == cert_model.cert_pem
    assert self_signed_cert_with_ext.public_key().public_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode() == cert_model.public_key_pem

    assert len(subject) == len(cert_model.subject.all())
    assert self_signed_cert_with_ext.subject.public_bytes().hex().upper() == cert_model.subject_public_bytes

    assert (now - cert_model.created_at).total_seconds() < 60

    assert cert_model.is_ca is True
    assert cert_model.is_root_ca is True
    assert cert_model.is_end_entity is False


@pytest.mark.django_db
def test_key_usage_ext(self_signed_cert_with_ext) -> None:
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)

    assert cert_model.key_usage_extension is not None
    kue = cert_model.key_usage_extension
    assert kue.digital_signature is True
    assert kue.content_commitment is True
    assert kue.key_encipherment is True
    assert kue.data_encipherment is True
    assert kue.key_agreement is True
    assert kue.key_cert_sign is True
    assert kue.crl_sign is True
    assert kue.encipher_only is True
    assert kue.decipher_only is True


@pytest.mark.django_db
def test_san_ext(self_signed_cert_with_ext) -> None:
    """Test the SubjectAlternativeNameExtension is correctly stored.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)

    assert cert_model.subject_alternative_name_extension is not None
    san_ext = cert_model.subject_alternative_name_extension
    # Check that all GeneralName types are present
    assert any(d.value == DNS_NAME_VALUE for d in san_ext.dns_names.all())
    assert any(r.value == RFC822_EMAIL for r in san_ext.rfc822_names.all())
    assert any(u.value == URI_VALUE for u in san_ext.uniform_resource_identifiers.all())
    # DirectoryName check
    assert san_ext.directory_names.count() == 1
    dir_name = san_ext.directory_names.first()
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_name.names.all())
    # RegisteredID check
    assert any(r.value == REGISTERED_ID_OID for r in san_ext.registered_ids.all())
    # IPAddress check
    assert any(ip.value == IP_ADDRESS_VALUE for ip in san_ext.ip_addresses.all())
    # OtherName check
    assert san_ext.other_names.count() == 1
    other_name = san_ext.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT

@pytest.mark.django_db
def test_ian_ext(self_signed_cert_with_ext) -> None:
    """Test the IssuerAlternativeNameExtension is correctly stored.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)

    assert cert_model.issuer_alternative_name_extension is not None
    ian_ext = cert_model.issuer_alternative_name_extension
    # DNSName check
    assert any(d.value == DNS_NAME_VALUE for d in ian_ext.dns_names.all())
    # RFC822Name check
    assert any(r.value == RFC822_EMAIL for r in ian_ext.rfc822_names.all())
    # UniformResourceIdentifier check
    assert any(u.value == URI_VALUE for u in ian_ext.uniform_resource_identifiers.all())
    # DirectoryName check
    assert ian_ext.directory_names.count() == 1
    dir_name = ian_ext.directory_names.first()
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_name.names.all())
    # RegisteredID check
    assert any(r.value == REGISTERED_ID_OID for r in ian_ext.registered_ids.all())
    # IPAddress check
    assert any(ip.value == IP_ADDRESS_VALUE for ip in ian_ext.ip_addresses.all())
    # OtherName check
    assert ian_ext.other_names.count() == 1
    other_name = ian_ext.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT

@pytest.mark.django_db
def test_basic_constraints_ext(self_signed_cert_with_ext) -> None:
    """Test that the basic_constraints_extension is correctly saved and linked.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    assert cert_model.basic_constraints_extension is not None
    bce = cert_model.basic_constraints_extension
    assert bce.ca is True
    assert bce.path_length_constraint == 0

@pytest.mark.django_db
def test_authority_key_identifier_ext(self_signed_cert_with_ext):
    """Test that AuthorityKeyIdentifierExtension is correctly saved."""
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)

    # Check if the AKI extension is saved
    aki_ext = cert_model.authority_key_identifier_extension
    assert aki_ext is not None

    # Calculate the expected key_identifier as SHA-1 hash of the DER-encoded public key
    public_key = self_signed_cert_with_ext.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_key_identifier = hashlib.sha1(public_key_bytes).digest().hex().upper()
    assert aki_ext.key_identifier == expected_key_identifier

    # Check authority_cert_serial_number
    expected_serial_number = hex(self_signed_cert_with_ext.serial_number)[2:].upper()
    assert aki_ext.authority_cert_serial_number == expected_serial_number

    # TODO: Write GeneralName attr. test
    # Check authority_cert_issuer GeneralNames
    # Check RFC822Name
    assert any(r.value == RFC822_EMAIL for r in aki_ext.rfc822_names.all())

    # Check DNSName
    assert any(d.value == DNS_NAME_VALUE for d in aki_ext.dns_names.all())

    # Check UniformResourceIdentifier
    assert any(u.value == URI_VALUE for u in aki_ext.uniform_resource_identifiers.all())
    # Check DirectoryName
    assert aki_ext.directory_names.count() == 1
    dir_name = aki_ext.directory_names.first()
    dir_attrs = list(dir_name.names.all())
    assert any(attr.value == ORGANIZATION_NAME for attr in dir_attrs)

    # Check RegisteredID
    assert any(r.value == REGISTERED_ID_OID for r in aki_ext.registered_ids.all())

    # Check IPAddress
    assert any(ip.value == IP_ADDRESS_VALUE for ip in aki_ext.ip_addresses.all())

    # Check OtherName
    assert aki_ext.other_names.count() == 1
    other_name = aki_ext.other_names.first()
    assert other_name.type_id == OTHER_NAME_OID
    decoded_asn1, _ = decode(bytes.fromhex(other_name.value), asn1Spec=char.UTF8String())
    assert str(decoded_asn1) == OTHER_NAME_CONTENT


@pytest.mark.django_db
def test_subject_key_identifier_ext(self_signed_cert_with_ext):
    """Test that the SubjectKeyIdentifierExtension is correctly saved.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)

    # Check if the SKI extension is saved
    ski_ext = cert_model.subject_key_identifier_extension
    assert ski_ext is not None

    # Calculate the expected key_identifier as SHA-1 hash of the DER-encoded public key
    public_key = self_signed_cert_with_ext.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected_key_identifier = hashlib.sha1(public_key_bytes).digest().hex().upper()

    assert ski_ext.key_identifier == expected_key_identifier


@pytest.mark.django_db
def test_get_certificate_serializer(self_signed_cert_with_ext) -> None:
    """Test that get_certificate_serializer returns a serializer representing the same certificate.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    serializer = cert_model.get_certificate_serializer()
    loaded_cert = serializer.as_crypto()
    assert loaded_cert.fingerprint(hashes.SHA256()) == self_signed_cert_with_ext.fingerprint(hashes.SHA256())

@pytest.mark.django_db
def test_get_public_key_serializer(self_signed_cert_with_ext) -> None:
    """Test that get_public_key_serializer returns a serializer with the correct public key.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    pk_serializer = cert_model.get_public_key_serializer()
    loaded_key = pk_serializer.as_crypto()
    assert loaded_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ) == self_signed_cert_with_ext.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


@pytest.mark.django_db
def test_get_cert_by_sha256_fingerprint(self_signed_cert_with_ext) -> None:
    """Test looking up a certificate by its SHA256 fingerprint.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    fp = cert_model.sha256_fingerprint
    fetched = CertificateModel._get_cert_by_sha256_fingerprint(fp)
    assert fetched == cert_model

    fetched_lower = CertificateModel._get_cert_by_sha256_fingerprint(fp.lower())
    assert fetched_lower == cert_model


# ----------------- Test end entiy cert --------------------------

@pytest.mark.django_db
def test_ee_certificate(self_signed_cert_with_ext, rsa_private_key) -> None:
    """Test that a non-CA certificate is recognized correctly.

    Args:
        self_signed_cert_with_ext (x509.Certificate): A self-signed CA certificate fixture.
        rsa_private_key (rsa.RSAPrivateKey): The RSA private key fixture.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'End Entity'),
    ])
    issuer = self_signed_cert_with_ext.subject
    now = datetime.now(timezone.utc)
    end_entity_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10))
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )
    ee_model = CertificateModel.save_certificate(end_entity_cert)
    assert ee_model.is_ca is False
    assert ee_model.is_end_entity is True
    assert ee_model.is_root_ca is False


@pytest.mark.django_db
def test_subject_and_issuer_entries(self_signed_cert_with_ext) -> None:
    """Test that subject and issuer attributes are stored correctly as AttributeTypeAndValue.

    Args:
        self_signed_cert_with_ext (x509.Certificate): The certificate fixture with all extensions.
    """
    cert_model = CertificateModel.save_certificate(self_signed_cert_with_ext)
    subject_attrs = list(cert_model.subject.all())
    assert any(a.value == COMMON_NAME for a in subject_attrs)
    assert any(a.value == COUNTRY_NAME for a in subject_attrs)

    issuer_attrs = list(cert_model.issuer.all())
    assert len(issuer_attrs) == len(subject_attrs)
    assert {(a.oid, a.value) for a in issuer_attrs} == {(a.oid, a.value) for a in subject_attrs}
