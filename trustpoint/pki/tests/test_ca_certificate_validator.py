from django.test import TestCase

from cryptography import x509
from pki import validator
from .certificate_builder import CertificateBuilder


# class CaCertificateValidatorTest(TestCase):
#     _base_cert_builder: CertificateBuilder = CertificateBuilder().create_default_base()
#
#     def test_authority_key_identifier_missing(self):
#         cert = self._base_cert_builder.create_cert().certificate
#         cert_validator = validator.CertificateValidator(cert)
#         self.assertFalse = validator.CertificateValidator(cert)
#         self.assertIn(validator.CertificateError.EXT_AUTHORITY_KEY_ID_MISSING, cert_validator.errors)

    # def test_authority_key_identifier_is_critical(self):
    #     pass
    #
    # def test_authority_key_identifier_is_not_critical(self):
    #     pass
