import pytest


class MockCertificateSerializer:
    def as_pem(self):
        return b"-----BEGIN CERTIFICATE-----\nFAKE_PEM_CONTENT\n-----END CERTIFICATE-----"
    def as_der(self):
        return b"\x30\x82\x01\x0a\x02\x82"  # Beispiel-Inhalt
    def as_pkcs7_pem(self):
        return b"-----BEGIN PKCS7-----\nFAKE_PKCS7_CONTENT\n-----END PKCS7-----"
    def as_pkcs7_der(self):
        return b"\x30\x82\x02\x09\x06\x09\x2a"  # Beispiel-Inhalt

@pytest.fixture
def mock_certificate_serializer():
    return MockCertificateSerializer()

@pytest.fixture
def mock_certificate_collection_serializer(mock_certificate_serializer):
    return [mock_certificate_serializer, mock_certificate_serializer]
