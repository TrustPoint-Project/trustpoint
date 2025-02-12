import unittest
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from core.validator.path_validation.path_validation import CertificatePathValidator

def load_certs(filename):
    """Loads one or multiple PEM certificates from a file."""
    with open(filename, "rb") as f:
        pem_data = f.read()

    certs = []
    for cert_pem in pem_data.split(b"-----END CERTIFICATE-----"):
        cert_pem = cert_pem.strip()
        if cert_pem:
            cert_pem += b"\n-----END CERTIFICATE-----"
            certs.append(load_pem_x509_certificate(cert_pem, default_backend()))

    return certs

class TestCertificatePathValidator(unittest.TestCase):

    def run_test_case(self, case_number, expected_result):
        """ Helper method to load certs, run validation, and compare the result with expected. """
        try:
            trusted_certs = load_certs(f"case_{case_number}/root.pem")
            intermediate_certs = load_certs(f"case_{case_number}/intermediates.pem")
            cert_to_validate = load_certs(f"case_{case_number}/leaf.pem")

            validator = CertificatePathValidator(
                trusted_certs=trusted_certs,
                intermediates=intermediate_certs,
                cert_to_validate=cert_to_validate[0]
            )

            is_valid, error_message = validator.validate()
            self.assertEqual(is_valid, expected_result, f"Case {case_number} failed: {error_message}")

        except Exception as e:
            self.fail(f"Unexpected error in Case {case_number}: {e}")

    def test_case_1(self):
        """Case 1: Valid certificate chain:

            [0] CN=intermediate_2 (Issuer: CN=intermediate_1)
            [1] CN=intermediate_1 (Issuer: CN=root_ca)
        """
        with self.subTest("Case 1 - Valid Chain"):
            self.run_test_case(1, True)

    def test_case_2(self):
        """ Case 2: Valid certificate chain:

            [0] CN=EE 99 (Issuer: CN=intermediate_3)
            [1] CN=intermediate_3 (Issuer: CN=intermediate_2)
            [2] CN=intermediate_2 (Issuer: CN=intermediate_1)
            [3] CN=intermediate_1 (Issuer: CN=root_ca)
            [4] CN=root_ca (Issuer: CN=root_ca)
        """
        with self.subTest("Case 2 - Valid Long Chain"):
            self.run_test_case(2, True)

    def test_case_3(self):
        """ Case 3: Valid certificate chain:

            [0] CN=EE 99 (Issuer: CN=intermediate_3)
            [1] CN=intermediate_3 (Issuer: CN=intermediate_2)
            [2] CN=intermediate_2 (Issuer: CN=intermediate_1)
            [3] CN=intermediate_1 (Issuer: CN=root_ca)
        """
        with self.subTest("Case 3 - Valid but Missing Self-Signed Root"):
            self.run_test_case(3, True)

    def test_case_4(self):
        """ Case 4: No valid issuer found:

        No valid issuer found for: CN=intermediate_3 (Issuer: CN=intermediate_2)
        """
        with self.subTest("Case 4 - No Valid Issuer"):
            self.run_test_case(4, False)

if __name__ == "__main__":
    unittest.main()
