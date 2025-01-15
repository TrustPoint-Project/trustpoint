
import pytest
from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7


def test_certificate_serializer_init_with_bytes(pem_encoded_cert):
    """Test that CertificateSerializer correctly initializes from PEM bytes.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    serializer = CertificateSerializer(pem_encoded_cert)
    assert isinstance(serializer.as_crypto(), x509.Certificate)
    assert serializer.as_pem() == pem_encoded_cert


def test_certificate_serializer_init_with_str(pem_encoded_cert):
    """Test that CertificateSerializer correctly initializes from a PEM string.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    pem_str = pem_encoded_cert.decode('utf-8')
    serializer = CertificateSerializer(pem_str)
    assert isinstance(serializer.as_crypto(), x509.Certificate)
    assert serializer.as_pem() == pem_encoded_cert


def test_certificate_serializer_init_with_x509_object(self_signed_certificate):
    """Test that CertificateSerializer correctly initializes from an x509.Certificate object.

    Args:
        self_signed_certificate (x509.Certificate): A self-signed certificate object for testing.
    """
    serializer = CertificateSerializer(self_signed_certificate)
    assert isinstance(serializer.as_crypto(), x509.Certificate)
    assert serializer.as_crypto() == self_signed_certificate


def test_certificate_serializer_init_with_serializer(pem_encoded_cert):
    """Test that CertificateSerializer correctly initializes from another CertificateSerializer instance.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    existing = CertificateSerializer(pem_encoded_cert)
    new_serializer = CertificateSerializer(existing)
    assert isinstance(new_serializer.as_crypto(), x509.Certificate)
    assert new_serializer.as_pem() == pem_encoded_cert


def test_certificate_serializer_init_raises_type_error():
    """Test that CertificateSerializer raises a TypeError for unsupported types."""
    with pytest.raises(TypeError):
        CertificateSerializer(12345)


def test_certificate_serializer_init_raises_value_error():
    """Test that CertificateSerializer raises a ValueError for malformed data."""
    with pytest.raises(ValueError):
        CertificateSerializer(b'Not a valid cert')

def test_certificate_serializer_as_pem(pem_encoded_cert):
    """Test that CertificateSerializer.as_pem() returns PEM-encoded data.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    serializer = CertificateSerializer(pem_encoded_cert)
    output = serializer.as_pem()
    assert output == pem_encoded_cert


def test_certificate_serializer_as_der(der_encoded_cert):
    """Test that CertificateSerializer.as_der() returns DER-encoded data.

    Args:
        der_encoded_cert (bytes): A valid DER-encoded certificate for testing.
    """
    serializer = CertificateSerializer(der_encoded_cert)
    output = serializer.as_der()
    assert output == der_encoded_cert

def test_certificate_serializer_as_pkcs7_pem(pem_encoded_cert):
    """Test that CertificateSerializer.as_pkcs7_pem() returns PKCS#7 PEM-encoded data.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    serializer = CertificateSerializer(pem_encoded_cert)
    pkcs7_pem = serializer.as_pkcs7_pem()
    assert isinstance(pkcs7_pem, bytes)
    assert b'-----BEGIN PKCS7-----' in pkcs7_pem

    parsed_certs = pkcs7.load_pem_pkcs7_certificates(pkcs7_pem)
    assert len(parsed_certs) == 1
    assert isinstance(parsed_certs[0], x509.Certificate)


def test_certificate_serializer_as_pkcs7_der(pem_encoded_cert):
    """Test that CertificateSerializer.as_pkcs7_der() returns PKCS#7 DER-encoded data.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    serializer = CertificateSerializer(pem_encoded_cert)
    pkcs7_der = serializer.as_pkcs7_der()
    assert isinstance(pkcs7_der, bytes)

    parsed_certs = pkcs7.load_der_pkcs7_certificates(pkcs7_der)
    assert len(parsed_certs) == 1
    assert isinstance(parsed_certs[0], x509.Certificate)



def test_certificate_serializer_public_key_serializer(pem_encoded_cert):
    """Test accessing the public_key_serializer property.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    serializer = CertificateSerializer(pem_encoded_cert)
    pks = serializer.public_key_serializer
    assert pks is not None
    assert pks is serializer.public_key_serializer


def test_certificate_collection_serializer_init_with_bytes(pem_encoded_cert):
    """Test that CertificateCollectionSerializer initializes from PEM bytes.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    data = pem_encoded_cert + pem_encoded_cert
    collection_serializer = CertificateCollectionSerializer(data)
    assert len(collection_serializer) == 2


def test_certificate_collection_serializer_init_with_str(pem_encoded_cert):
    """Test that CertificateCollectionSerializer initializes from a PEM string.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    pem_str = pem_encoded_cert.decode('utf-8') + pem_encoded_cert.decode('utf-8')
    collection_serializer = CertificateCollectionSerializer(pem_str)
    assert len(collection_serializer) == 2


def test_certificate_collection_serializer_init_with_list(self_signed_certificate):
    """Test that CertificateCollectionSerializer initializes from a list of certificates.

    Args:
        self_signed_certificate (x509.Certificate): A self-signed certificate object for testing.
    """
    cert_as_bytes = self_signed_certificate.public_bytes(serialization.Encoding.PEM)
    cert_as_obj = self_signed_certificate
    input_list = [cert_as_bytes, cert_as_obj]
    collection_serializer = CertificateCollectionSerializer(input_list)
    assert len(collection_serializer) == 2


def test_certificate_collection_serializer_as_pem_list(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.as_pem_list() returns a list of PEM-encoded certs.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    pem_list = collection.as_pem_list()
    assert len(pem_list) == 2
    for pem in pem_list:
        assert pem == pem_encoded_cert


def test_certificate_collection_serializer_as_der_list(der_encoded_cert):
    """Test that CertificateCollectionSerializer.as_der_list() returns a list of DER-encoded certs.

    Args:
        der_encoded_cert (bytes): A valid DER-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([der_encoded_cert, der_encoded_cert])
    der_list = collection.as_der_list()
    assert len(der_list) == 2
    for der_data in der_list:
        assert der_data == der_encoded_cert


def test_certificate_collection_serializer_as_certificate_serializer_list(pem_encoded_cert):
    """Test that as_certificate_serializer_list() returns a list of CertificateSerializer objects.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    serializer_list = collection.as_certificate_serializer_list()
    assert len(serializer_list) == 2
    assert all(isinstance(item, CertificateSerializer) for item in serializer_list)


def test_certificate_collection_serializer_as_crypto_list(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.as_crypto_list() returns x509.Certificate objects.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection_serializer = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    crypto_list = collection_serializer.as_crypto_list()
    assert len(crypto_list) == 2
    assert all(isinstance(cert, x509.Certificate) for cert in crypto_list)


def test_certificate_collection_serializer_as_pem(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.as_pem() returns concatenated PEM.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection_serializer = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    pem_output = collection_serializer.as_pem()
    expected = pem_encoded_cert + pem_encoded_cert
    assert pem_output == expected


def test_certificate_collection_serializer_as_pkcs7_pem(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.as_pkcs7_pem() returns PKCS#7 PEM-encoded data.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    pkcs7_pem = collection.as_pkcs7_pem()
    assert isinstance(pkcs7_pem, bytes)
    assert b'-----BEGIN PKCS7-----' in pkcs7_pem

    parsed_certs = pkcs7.load_pem_pkcs7_certificates(pkcs7_pem)
    assert len(parsed_certs) == 2


def test_certificate_collection_serializer_as_pkcs7_der(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.as_pkcs7_der() returns PKCS#7 DER-encoded data.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    pkcs7_der = collection.as_pkcs7_der()
    assert isinstance(pkcs7_der, bytes)

    parsed_certs = pkcs7.load_der_pkcs7_certificates(pkcs7_der)
    assert len(parsed_certs) == 2


def test_certificate_collection_serializer_append(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.append() adds a new certificate to the collection.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection_serializer = CertificateCollectionSerializer([])
    assert len(collection_serializer) == 0

    collection_serializer.append(pem_encoded_cert)
    assert len(collection_serializer) == 1


def test_certificate_collection_serializer_extend(pem_encoded_cert):
    """Test that CertificateCollectionSerializer.extend() adds multiple certificates to the collection.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection_serializer = CertificateCollectionSerializer([pem_encoded_cert])
    initial_length = len(collection_serializer)

    another_serializer = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    collection_serializer.extend(another_serializer)

    assert len(collection_serializer) == initial_length + 2


def test_certificate_collection_serializer_invalid_type():
    """Test that CertificateCollectionSerializer raises TypeError for unsupported types."""
    with pytest.raises(TypeError):
        CertificateCollectionSerializer(12345)


def test_certificate_collection_serializer_invalid_value():
    """Test that CertificateCollectionSerializer raises ValueError for malformed data."""
    with pytest.raises(ValueError):
        CertificateCollectionSerializer(b'invalid data')


def test_certificate_collection_serializer_certificate_serializer_iterator(pem_encoded_cert):
    """Test certificate_serializer_iterator() returns an iterator of CertificateSerializer objects.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    iterator = collection.certificate_serializer_iterator()
    items = list(iterator)
    assert len(items) == 2
    assert all(isinstance(i, CertificateSerializer) for i in items)


def test_certificate_collection_serializer_crypto_iterator(pem_encoded_cert):
    """Test crypto_iterator() returns an iterator of x509.Certificate objects.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    iterator = collection.crypto_iterator()
    items = list(iterator)
    assert len(items) == 2
    assert all(isinstance(i, x509.Certificate) for i in items)


def test_certificate_collection_serializer_pem_iterator(pem_encoded_cert):
    """Test pem_iterator() returns an iterator of PEM-encoded bytes.

    Args:
        pem_encoded_cert (bytes): A valid PEM-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([pem_encoded_cert, pem_encoded_cert])
    iterator = collection.pem_iterator()
    items = list(iterator)
    assert len(items) == 2
    assert all(i == pem_encoded_cert for i in items)


def test_certificate_collection_serializer_der_iterator(der_encoded_cert):
    """Test der_iterator() returns an iterator of DER-encoded bytes.

    Args:
        der_encoded_cert (bytes): A valid DER-encoded certificate for testing.
    """
    collection = CertificateCollectionSerializer([der_encoded_cert, der_encoded_cert])
    iterator = collection.der_iterator()
    items = list(iterator)
    assert len(items) == 2
    assert all(i == der_encoded_cert for i in items)
