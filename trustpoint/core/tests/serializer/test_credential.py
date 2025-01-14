
import pytest
from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
)
from core.serializer.credential import (
    CredentialSerializer,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate


def test_init_from_bytes_pkcs12(pkcs12_data: bytes) -> None:
    """Test CredentialSerializer init from PKCS#12 bytes."""
    serializer = CredentialSerializer(pkcs12_data)
    assert isinstance(serializer.credential_private_key, PrivateKeySerializer)
    assert isinstance(serializer.credential_certificate, CertificateSerializer)
    assert isinstance(serializer.additional_certificates, CertificateCollectionSerializer)
    assert len(serializer.additional_certificates) == 1


def test_init_from_pkcs12_object(pkcs12_data: bytes) -> None:
    """Test CredentialSerializer init from a PKCS12KeyAndCertificates object."""
    pkcs12_obj = pkcs12.load_pkcs12(pkcs12_data, None)
    serializer = CredentialSerializer(pkcs12_obj)
    assert isinstance(serializer.credential_private_key, PrivateKeySerializer)
    assert isinstance(serializer.credential_certificate, CertificateSerializer)
    assert isinstance(serializer.additional_certificates, CertificateCollectionSerializer)
    assert len(serializer.additional_certificates) == 1


def test_init_from_credential_serializer(pkcs12_data: bytes) -> None:
    """Test init from another CredentialSerializer instance."""
    original = CredentialSerializer(pkcs12_data)
    clone = CredentialSerializer(original)
    assert clone.credential_private_key.as_crypto().private_numbers() == \
           original.credential_private_key.as_crypto().private_numbers()
    assert clone.credential_certificate.as_pem() == original.credential_certificate.as_pem()
    assert len(clone.additional_certificates) == len(original.additional_certificates)


def test_init_from_tuple_2(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test init from tuple of length 2 => (private_key, certificate)."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    assert isinstance(serializer.credential_private_key, PrivateKeySerializer)
    assert isinstance(serializer.credential_certificate, CertificateSerializer)
    assert serializer.additional_certificates is None


def test_init_from_tuple_3(
        rsa_private_key: RSAPrivateKey,
        self_signed_cert: Certificate,
        second_self_signed_cert: Certificate) -> None:
    """Test init from tuple of length 3 => (private_key, certificate, additional_certs)."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert, [second_self_signed_cert]))
    assert isinstance(serializer.credential_private_key, PrivateKeySerializer)
    assert isinstance(serializer.credential_certificate, CertificateSerializer)
    assert isinstance(serializer.additional_certificates, CertificateCollectionSerializer)
    assert len(serializer.additional_certificates) == 1


def test_init_from_tuple_invalid_length() -> None:
    """Test that an invalid tuple length raises an error."""
    with pytest.raises(TypeError):
        CredentialSerializer((123,))
    with pytest.raises(TypeError):
        CredentialSerializer((123, 456, 789, 999))


def test_init_invalid_type() -> None:
    """Test that passing an unsupported credential type raises TypeError."""
    with pytest.raises(TypeError):
        CredentialSerializer(123)


def test_init_invalid_pkcs12() -> None:
    """Test that invalid PKCS#12 data raises ValueError."""
    with pytest.raises(ValueError):
        CredentialSerializer(b'invalid pkcs12 data')


def test_from_crypto_pkcs12_direct(pkcs12_data: bytes) -> None:
    """Test that _from_crypto_pkcs12 returns the expected (PrivateKeySerializer, CertificateSerializer, CertCollection)."""
    pkcs12_obj = pkcs12.load_pkcs12(pkcs12_data, None)
    priv_key, cert_ser, certs_coll = CredentialSerializer._from_crypto_pkcs12(pkcs12_obj)
    assert isinstance(priv_key, PrivateKeySerializer)
    assert isinstance(cert_ser, CertificateSerializer)
    assert isinstance(certs_coll, CertificateCollectionSerializer)


def test_from_bytes_pkcs12_direct(pkcs12_data: bytes) -> None:
    """Test that _from_bytes_pkcs12 calls _from_crypto_pkcs12 internally and returns expected results."""
    priv_key, cert_ser, certs_coll = CredentialSerializer._from_bytes_pkcs12(pkcs12_data, None)
    assert isinstance(priv_key, PrivateKeySerializer)
    assert isinstance(cert_ser, CertificateSerializer)
    assert isinstance(certs_coll, CertificateCollectionSerializer)


def test_from_bytes_pkcs12_wrong_password(pkcs12_data: bytes) -> None:
    """Test that a wrong password triggers a ValueError."""
    with pytest.raises(ValueError) as exc_info:
        CredentialSerializer(pkcs12_data, password=b'wrongpassword')
    assert 'Failed to load credential' in str(exc_info.value)


def test_serialize_calls_as_pkcs12(pkcs12_data: bytes) -> None:
    """Test that serialize() returns PKCS#12 bytes (calls as_pkcs12 internally)."""
    serializer = CredentialSerializer(pkcs12_data)
    serialized = serializer.serialize()
    parsed = pkcs12.load_pkcs12(serialized, None)
    assert parsed is not None
    assert isinstance(parsed.key, rsa.RSAPrivateKey)


def test_as_pkcs12(pkcs12_data: bytes) -> None:
    """Test as_pkcs12 explicitly with optional password."""
    serializer = CredentialSerializer(pkcs12_data)
    pkcs12_bytes = serializer.as_pkcs12(password=b'mypwd', friendly_name=b'mycred')
    with pytest.raises(ValueError):
        pkcs12.load_pkcs12(pkcs12_bytes, b'wrong')
    parsed_correct = pkcs12.load_pkcs12(pkcs12_bytes, b'mypwd')
    assert isinstance(parsed_correct.key, rsa.RSAPrivateKey)

def test_len_without_additional_certs(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test __len__ returns 1 if no additional certs."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    assert len(serializer) == 1


def test_len_with_additional_certs(pkcs12_data: bytes) -> None:
    """Test __len__ with one additional certificate in PKCS#12 data."""
    serializer = CredentialSerializer(pkcs12_data)
    assert len(serializer) == 2


def test_get_as_separate_pem_files_pkcs8(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test get_as_separate_pem_files with PKCS8 format."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    priv_pem, cert_pem, add_pem = serializer.get_as_separate_pem_files(
        private_key_format=CredentialSerializer.PrivateKeyFormat.PKCS8,
        password=b'secret'
    )
    assert b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in priv_pem
    assert b'-----BEGIN CERTIFICATE-----' in cert_pem
    assert add_pem is None


def test_get_as_separate_pem_files_pkcs1(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test get_as_separate_pem_files with PKCS1 format."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    priv_der, cert_pem, add_pem = serializer.get_as_separate_pem_files(
        private_key_format=CredentialSerializer.PrivateKeyFormat.PKCS1,
        password=None
    )
    assert b'PRIVATE KEY' in priv_der or b'\x30\x82' in priv_der
    assert b'-----BEGIN CERTIFICATE-----' in cert_pem
    assert add_pem is None


def test_get_as_separate_pem_files_invalid_format(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test get_as_separate_pem_files raises ValueError for unsupported private_key_format."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    with pytest.raises(ValueError):
        serializer.get_as_separate_pem_files(private_key_format='SOME_INVALID_FORMAT')


def test_credential_private_key_setter(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate, rsa_private_key_alt) -> None:
    """Test the credential_private_key property setter."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    original = serializer.credential_private_key.as_crypto().private_numbers()

    new_key_serializer = PrivateKeySerializer(rsa_private_key)
    serializer.credential_private_key = new_key_serializer
    updated = serializer.credential_private_key.as_crypto().private_numbers()
    assert updated != original


def test_credential_certificate_setter(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate, second_self_signed_cert: Certificate) -> None:
    """Test the credential_certificate property setter."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    original_pem = serializer.credential_certificate.as_pem()

    new_cert_serializer = CertificateSerializer(second_self_signed_cert)
    serializer.credential_certificate = new_cert_serializer
    updated_pem = serializer.credential_certificate.as_pem()
    assert updated_pem != original_pem


def test_additional_certificates_setter(pkcs12_data, second_self_signed_cert: Certificate) -> None:
    """Test the additional_certificates property setter."""
    serializer = CredentialSerializer(pkcs12_data)
    original_len = len(serializer.additional_certificates)

    new_coll = CertificateCollectionSerializer([second_self_signed_cert, second_self_signed_cert])
    serializer.additional_certificates = new_coll

    assert len(serializer.additional_certificates) == 2
    assert len(serializer) == 1 + 2


def test_all_certificates_no_additional(rsa_private_key: RSAPrivateKey, self_signed_cert: Certificate) -> None:
    """Test all_certificates when no additional certs exist."""
    serializer = CredentialSerializer((rsa_private_key, self_signed_cert))
    all_certs = serializer.all_certificates
    assert len(all_certs) == 1
    assert all_certs.as_pem() == serializer.credential_certificate.as_pem()


def test_all_certificates_with_additional(pkcs12_data: bytes) -> None:
    """Test all_certificates when additional certs exist."""
    serializer = CredentialSerializer(pkcs12_data)
    all_certs = serializer.all_certificates
    assert len(all_certs) == 2


def test_get_encryption_algorithm() -> None:
    """Test _get_encryption_algorithm with and without password."""
    algo_with_password = CredentialSerializer._get_encryption_algorithm(password=b'secret')
    assert isinstance(algo_with_password, serialization.BestAvailableEncryption)

    algo_no_password = CredentialSerializer._get_encryption_algorithm(None)
    assert isinstance(algo_no_password, serialization.NoEncryption)


def test_load_pkcs12_valid(pkcs12_data: bytes) -> None:
    """Test _load_pkcs12 returns expected tuple (key, cert, additional_certs)."""
    key, cert, additional_certs = CredentialSerializer._load_pkcs12(pkcs12_data, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert isinstance(cert, x509.Certificate)
    assert isinstance(additional_certs, list)
    assert len(additional_certs) == 1


def test_load_pkcs12_invalid() -> None:
    """Test _load_pkcs12 raises ValueError on invalid data."""
    with pytest.raises(ValueError):
        CredentialSerializer._load_pkcs12(b'invalid data', password=None)
