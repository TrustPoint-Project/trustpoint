import datetime
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate, oid

# ------------------------- file builder fixtures --------------------

class MockCertificateSerializer:
    def as_pem(self):
        return b'-----BEGIN CERTIFICATE-----\nFAKE_PEM_CONTENT\n-----END CERTIFICATE-----'
    def as_der(self):
        return b'\x30\x82\x01\x0a\x02\x82'
    def as_pkcs7_pem(self):
        return b'-----BEGIN PKCS7-----\nFAKE_PKCS7_CONTENT\n-----END PKCS7-----'
    def as_pkcs7_der(self):
        return b'\x30\x82\x02\x09\x06\x09\x2a'

@pytest.fixture
def mock_certificate_serializer():
    return MockCertificateSerializer()

@pytest.fixture
def mock_certificate_collection_serializer(mock_certificate_serializer):
    return [mock_certificate_serializer, mock_certificate_serializer]


@pytest.fixture
def rsa_private_key() -> RSAPrivateKey:
    """Generate an RSA private key for testing purposes.

    Returns:
        rsa.RSAPrivateKey: A generated private key that can be used for certificate creation.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

# ----------------------- Serializer fixture --------------------

@pytest.fixture
def self_signed_certificate(rsa_private_key: RSAPrivateKey) -> Certificate:
    """Generate a self-signed x509 certificate for testing.

    Args:
        rsa_private_key (rsa.RSAPrivateKey): A private key used to sign the certificate.

    Returns:
        x509.Certificate: A self-signed certificate.
    """
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, 'TestState'),
        x509.NameAttribute(oid.NameOID.LOCALITY_NAME, 'TestCity'),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'TestOrg'),
        x509.NameAttribute(oid.NameOID.COMMON_NAME, 'localhost'),
    ])
    issuer = subject  # Self-signed
    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + timedelta(days=30)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]),
            critical=False,
        )
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )



@pytest.fixture
def pem_encoded_cert(self_signed_certificate: Certificate) -> Certificate:
    """Provide a PEM-encoded version of a self-signed certificate.

    Args:
        self_signed_certificate (x509.Certificate): A self-signed certificate.

    Returns:
        bytes: PEM-encoded certificate data.
    """
    return self_signed_certificate.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def der_encoded_cert(self_signed_certificate: Certificate) -> bytes:
    """Provide a DER-encoded version of a self-signed certificate.

    Args:
        self_signed_certificate (x509.Certificate): A self-signed certificate.

    Returns:
        bytes: DER-encoded certificate data.
    """
    return self_signed_certificate.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def rsa_private_key_alt() -> RSAPrivateKey:
    """Generate a second RSA private key for testing (e.g. to test mismatched keys)."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


@pytest.fixture
def self_signed_cert(rsa_private_key: RSAPrivateKey) -> Certificate:
    """Generate a self-signed certificate for testing."""
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, 'TestState'),
        x509.NameAttribute(oid.NameOID.LOCALITY_NAME, 'TestCity'),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'TestOrg'),
        x509.NameAttribute(oid.NameOID.COMMON_NAME, 'localhost'),
    ])
    issuer = subject  # self-signed
    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + timedelta(days=30)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost')]),
            critical=False,
        )
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256())
    )


@pytest.fixture
def second_self_signed_cert(rsa_private_key_alt: RSAPrivateKey) -> x509.Certificate:
    """Generate a second self-signed certificate for 'additional certificates' testing."""
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COUNTRY_NAME, 'DE'),
        x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, 'AltState'),
        x509.NameAttribute(oid.NameOID.LOCALITY_NAME, 'AltCity'),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'AltOrg'),
        x509.NameAttribute(oid.NameOID.COMMON_NAME, 'example.org'),
    ])
    issuer = subject
    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + timedelta(days=365)

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key_alt.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .sign(private_key=rsa_private_key_alt, algorithm=hashes.SHA256())
    )


@pytest.fixture
def pkcs12_data(
    rsa_private_key: RSAPrivateKey,
    self_signed_cert: Certificate,
    second_self_signed_cert: Certificate) -> bytes:
    """Create PKCS#12 data with one key/cert pair and an additional certificate."""
    additional_certs = [second_self_signed_cert]
    friendly_name = b'test_cred'
    return pkcs12.serialize_key_and_certificates(
        name=friendly_name,
        key=rsa_private_key,
        cert=self_signed_cert,
        cas=additional_certs,
        encryption_algorithm=serialization.NoEncryption()
    )
