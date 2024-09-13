from django.test import TestCase

from cryptography import x509
from pki import validator
from .certificate_builder import CertificateBuilder


class CertificateValidatorTest(TestCase):
    _default_cert: x509.Certificate = CertificateBuilder().create_default_base().create_cert().certificate

    def test_version_1(self):
        # TODO: legacy - openssl
        pass

    def test_version_2(self):
        # TODO: legacy - openssl
        pass

    def test_version_3(self):
        cert_validator = validator.CertificateValidator(self._default_cert)
        self.assertTrue(cert_validator.is_valid)
        self.assertListEqual([], cert_validator.errors)
        self.assertListEqual([], cert_validator.warnings)

    def test_serial_number(self):
        # TODO: all variants
        pass

    def test_signature_oid_entries(self):
        # TODO: all variants
        pass

    def test_subject(self):
        # TODO: all variants
        pass

    def test_issuer(self):
        # TODO: all variants
        pass

