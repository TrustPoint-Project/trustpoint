import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pyasn1_modules.rfc7508 import Algorithm

# Example code for a function which handles the CSR
# from est.services import handle_csr

"""Test class for the EST protocol. 
Here, the core logic for EST should be tested, as well as the behavior of the models.
Note: This is just a dummy class with dummy methods. 
TODO: This is not tested!
"""
class TestESTServices(unittest.TestCase):
    def setUp(self):
        """Set up a sample CSR for testing."""
        # Generate a private key
        # self.private_key = rsa.generate_private_key(
        #     public_exponent=65537,
        #     key_size=2048,
        # )
        #

        # # Create a CSR
        # self.csr = x509.CertificateSigningRequestBuilder().subject_name(
        #     x509.Name([
        #         x509.NameAttribute(NameOID.COMMON_NAME, u"test.example.com"),
        #         x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        #     ])
        # ).sign(self.private_key, None)
        #
        # # Convert CSR to PEM format
        # self.csr_pem = self.csr.public_bytes(serialization.Encoding.PEM)

    def test_output(self):
        print("Test")

    # # Example method which should sign the certificate
    # @patch('est.services.sign_certificate')
    # def test_handle_csr_valid_input(self, mock_sign_certificate):
    #     """Test that a valid CSR is processed correctly."""
    #     # Mock the signing function to return a dummy certificate
    #     mock_sign_certificate.return_value = b"-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----"
    #
    #     # Call the handle_csr function
    #     response = handle_csr(self.csr_pem)
    #
    #     # Check if the response is a certificate in PEM format
    #     self.assertIn(b"-----BEGIN CERTIFICATE-----", response)
    #     self.assertIn(b"-----END CERTIFICATE-----", response)
    #     mock_sign_certificate.assert_called_once_with(self.csr)
    #
    # def test_handle_csr_invalid_input(self):
    #     """Test that an invalid CSR raises an error."""
    #     invalid_csr = b"-----INVALID CSR-----"
    #
    #     with self.assertRaises(ValueError) as context:
    #         handle_csr(invalid_csr)
    #
    #     self.assertEqual(str(context.exception), "Invalid CSR format")

    # # Example method which should sign the certificate
    # @patch('est.services.sign_certificate')
    # def test_handle_csr_empty_subject(self, mock_sign_certificate):
    #     """Test that a CSR with an empty subject is rejected."""
    #     # Create a CSR with an empty subject
    #     csr_empty_subject = x509.CertificateSigningRequestBuilder().subject_name(
    #         x509.Name([])
    #     ).sign(self.private_key, None)
    #     csr_pem_empty_subject = csr_empty_subject.public_bytes(serialization.Encoding.PEM)
    #
    #     with self.assertRaises(ValueError) as context:
    #        handle_csr(csr_pem_empty_subject)
    #
    #     self.assertEqual(str(context.exception), "CSR subject cannot be empty")
    #     mock_sign_certificate.assert_not_called()

if __name__ == "__main__":
    unittest.main()
