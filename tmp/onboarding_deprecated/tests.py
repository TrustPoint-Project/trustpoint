"""Module that contains all tests corresponding to the Onboarding application."""

# ruff: noqa: PT009, PT027, SLF001 # unittest-style asserts are used by django and may produce more meaningful errors

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from devices_deprecated.models import Device
from django.test import TestCase
from pki.management.commands.reset_db import Command as ResetDBCommand
from pki.management.commands.test_ts import Command as TestTSCommand
from pki.models import DomainModel
from pki.util.keys import KeyGenerator, SignatureSuite

from onboarding_deprecated.crypto_backend import CryptoBackend as Crypt
from onboarding_deprecated.crypto_backend import OnboardingError
from onboarding_deprecated.models import DownloadOnboardingProcess, ManualCsrOnboardingProcess, OnboardingProcess, _onboarding_processes


class CryptoBackendTests(TestCase):
    """Tests the CryptoBackend class."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Initializes the test DB with demo data.

        Using setUpClass might cause some tests that modify DB to impact others,
        but this is not the case in onboarding as tests do not modify endpoint profiles and CAs.
        """
        # init DB for testing (this runs against the test DB so not necessary to clear first)
        # TODO(Air): Consider demo init outside of command when also using for unit tests
        print('Initializing test DB with demo data...')
        ResetDBCommand().handle()


    def test_pbkdf2_hmac_sha256(self):
        """Tests the pbkdf2_hmac_sha256 method."""
        hexpass = 'totemoanzendesu'
        hexsalt = 'shiochan'
        message = b'testing123'
        iterations = 9001
        dklen = 32
        expected = '5177c2d5d7fdeb832878ebaa27a9b364665213422f975ef02f5d9436440739b7'
        result = Crypt.pbkdf2_hmac_sha256(hexpass, hexsalt, message, iterations, dklen)
        self.assertEqual(result, expected)

    def test_pbkdf2_hmac_sha256_default(self):
        """Tests the pbkdf2_hmac_sha256 method with empty/default default parameters.

        This test will fail if PBKDF2_ITERATIONS or PBKDF2_DKLEN are changed.
        """
        hexpass = ''
        hexsalt = ''
        expected = '9e2610afee4ae40dd3776f14f54139586cea35ff0dfd4729f49a0c36b506f4f0'
        result = Crypt.pbkdf2_hmac_sha256(hexpass, hexsalt)
        self.assertEqual(result, expected)

    def test__get_ca_missingdata(self):
        """Tests the _get_ca method raising onboarding error if there is no endpoint profile or issuing CA."""
        device = Device() # no endpoint profile
        with self.assertRaises(OnboardingError):
            Crypt._get_ca(device)
        ep = DomainModel(unique_name='test_endpoint')
        device.domain_profile = ep # endpoint profile without issuing CA
        with self.assertRaises(OnboardingError):
            Crypt._get_ca(device)

    # def test__sign_ldevid_no_serialno(self):
    #     """Tests the _sign_ldevid method if the device has no serial number set."""
    #     device = Device()
    #     device.domain_profile = DomainModel(unique_name='test_endpoint')
    #     private_key = Crypt._gen_private_key()
    #     with self.assertRaises(OnboardingError):
    #         Crypt._sign_ldevid(private_key.public_key(), device)

    # def test__sign_ldevid(self):
    #     """Tests the _sign_ldevid method."""
    #     device = Device(serial_number='1234567890abcdef')
    #     device.domain_profile = DomainModel.objects.get(unique_name='default')
    #     private_key = Crypt._gen_private_key()
    #     ldevid = Crypt._sign_ldevid(private_key.public_key(), device)
    #     self.assertIsInstance(ldevid, x509.Certificate, 'LDevID is not an instance of x509.Certificate.')
    #     self.assertEqual(ldevid.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value,
    #                      device.device_serial_number, 'Issued LDevID subject SN does not match device serial number.')

    @staticmethod
    def _gen_test_csr(device: Device) -> x509.CertificateSigningRequest:
        """Generates a test CSR."""
        private_key = KeyGenerator(SignatureSuite.RSA2048).generate_key()
        return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
          x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, device.device_serial_number),
          x509.NameAttribute(x509.NameOID.COMMON_NAME, 'client.trustpoint.ldevid.local'),
        ])).sign(private_key, hashes.SHA256())

    def test_sign_ldevid_from_csr(self):
        """Tests the sign_ldevid_from_csr method."""
        device = Device(serial_number='1234567890abcdef')
        device.domain_profile = DomainModel.objects.get(unique_name='default')
        csr = self._gen_test_csr(device).public_bytes(serialization.Encoding.PEM)
        ldevid = Crypt.sign_ldevid_from_csr(csr, device)
        try :
            ldevid = x509.load_pem_x509_certificate(ldevid)
        except ValueError:
            self.fail('sign_ldevid_from_csr did not return valid PEM certificate bytes.')
        self.assertIsInstance(ldevid, x509.Certificate, 'LDevID is not an instance of x509.Certificate.')
        self.assertEqual(ldevid.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value,
                         device.device_serial_number, 'Issued LDevID subject SN does not match device serial number.')


class OnboardingProcessTests(TestCase):
    """Tests for the the OnboardingProcess class and children."""
    def test_make_onboarding_process_existing_process(self):
        """Tests that make_onboarding_process returns any existing onboarding process for the device.

        (instead of making a new one)
        """
        device = Device(serial_number='1234567890abcdef')
        onboarding_process = ManualCsrOnboardingProcess(device)
        _onboarding_processes.append(onboarding_process)
        process = ManualCsrOnboardingProcess.make_onboarding_process(device)
        self.assertIs(process, onboarding_process, 'make_onboarding_process did not return existing process.')

    def test_make_onboarding_process_new_process(self):
        """Tests that make_onboarding_process creates a new onboarding process for the device."""
        device = Device(serial_number='1234567890abcdef')
        process = ManualCsrOnboardingProcess.make_onboarding_process(device)
        self.assertIsInstance(process, OnboardingProcess, 'make_onboarding_process did not return new process.')
        self.assertIn(process, _onboarding_processes, 'New process not added to _onboarding_processes.')
