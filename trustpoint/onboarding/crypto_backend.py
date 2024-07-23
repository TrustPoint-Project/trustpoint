"""This module provides cryptographic operations for use during the onboarding process.

This implementation is in testing stage and shall not be regarded as secure.
TODO sign_ldevid is Dragons with Lasers in central Berlin levels of a security risk TODO
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import NoEncryption, pkcs12
from util.strings import StringValidator
from pki.models import CertificateModel

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes, PrivateKeyTypes
    from cryptography.x509 import Certificate as X509Certificate
    from devices.models import Device

PBKDF2_ITERATIONS = 1000000
PBKDF2_DKLEN = 32

class OnboardingError(Exception):
    """Exception raised for errors in the onboarding process."""

    def __init__(self, message: str = 'An error occurred during onboarding.') -> None:
        """Initializes a new OnboardingError with a given message."""
        self.message = message
        super().__init__(self.message)


class CryptoBackend:
    """Provides cryptographic operations for use during the onboarding process."""

    @staticmethod
    def pbkdf2_hmac_sha256(
            hexpass: str,
            hexsalt: str,
            message: bytes = b'',
            iterations: int = PBKDF2_ITERATIONS,
            dklen: int = PBKDF2_DKLEN) -> str:
        """Calculates the HMAC signature of the trust store.

        Returns:
            HMAC_SHA256(PBKDF2_SHA256(hexpass, hexsalt, iterations, dklen), message)
        """
        pkey = hashlib.pbkdf2_hmac('sha256', hexpass.encode(), hexsalt.encode(), iterations, dklen)
        h = hmac.new(pkey, message, hashlib.sha256)
        return h.hexdigest()

    @staticmethod
    def get_trust_store() -> str:
        """Returns the trust store.

        TODO: Make location and included certificates configurable and verify that they are valid

        Returns:
            PEM string of the trust store (currently just a single HTTPS server certificate for testing purposes).

        Raises:
            FileNotFoundError: If the trust store file is not found.
        """
        with Path('../tests/data/x509/https_server.crt').open() as certfile:
            return certfile.read()

    @staticmethod
    def _get_ca(device: Device) -> CertificateModel:
        """Returns the CA private key, certificate and the CA certificate chain for a given device.

        Args:
            device (Device):
                The Device, whose domain profile to obtain the CA from.

        Returns:
            Certificate:
                The CA certificate, incl. private key, certificate and the CA certificate chain.
        """
        if not device.domain_profile:
            msg = 'No domain profile configured for device.'
            raise OnboardingError(msg)

        try:
            signing_ca = device.domain_profile.issuing_ca
        except AttributeError as e:
            msg = 'Could not obtain issuing CA from domain profile.'
            raise OnboardingError(msg) from e

        if not signing_ca:
            msg = 'No CA configured in domain profile.'
            raise OnboardingError(msg)

        # if not signing_ca.issuing_ca_certificate:
        #     msg = 'CA does not have issuing CA certificate.'
        #     raise OnboardingError(msg)
        #
        # return signing_ca.issuing_ca_certificate
        # TODO
        return signing_ca.certificates[0]


    @staticmethod
    def _sign_ldevid(pub_key: CertificatePublicKeyTypes, device: Device) -> X509Certificate:
        if not device.device_serial_number:
            exc_msg = 'No serial number provided.'
            raise OnboardingError(exc_msg)

        # subject = x509.Name([
        #     x509.NameAttribute(x509.NameOID.COMMON_NAME, 'ldevid.trustpoint.local'),
        #     x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, device.device_serial_number)
        # ])
        #
        # ca_certificate = CryptoBackend._get_ca(device)
        # # private_ca_key = ca_certificate.get_private_key_as_crypto()
        # ca_cert = ca_certificate.get_cert_as_crypto()
        #
        # cert = (
        #     x509.CertificateBuilder()
        #     .subject_name(subject)
        #     .issuer_name(ca_cert.subject)
        #     .public_key(pub_key)
        #     .serial_number(x509.random_serial_number())  # This is NOT the device serial number
        #     .not_valid_before(
        #         datetime.now(timezone.utc) - timedelta(hours=1)  # backdate a bit in case of client clock skew
        #     )
        #     .not_valid_after(
        #         # TODO(Air): configurable validity period
        #         datetime.now(timezone.utc) + timedelta(days=365)
        #         # Sign our certificate with our private key
        #     )
        #     .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        #     .sign(private_ca_key, hashes.SHA256())
        # )
        #
        # device_cert = CertificateModel()
        # device.ldevid = device_cert.save_certificate(cert)
        #
        # # need to keep track of the device once we send out a cert, even if onboarding fails afterwards
        # # TODO(Air): but do it here?
        # device.save()

        # return cert


    @staticmethod
    def sign_ldevid_from_csr(csr_pem: bytes, device: Device) -> bytes:
        """Signs a certificate signing request (CSR) with the onboarding CA.

        Args:
            csr_pem (bytes):
                The certificate signing request as bytes in PEM format.
            device (Device):
                The Device to associate the signed certificate with.

        Returns: The signed certificate as bytes in PEM format.

        Raises:
            OnboardingError: If the onboarding CA is not configured or not available.
        """
        csr = x509.load_pem_x509_csr(csr_pem)

        try:
            csr_serial = csr.subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
        except (x509.ExtensionNotFound, IndexError):
            csr_serial = None

        if not device.device_serial_number and not csr_serial:
            exc_msg = 'No serial number provided.'
            raise OnboardingError(exc_msg)
        if csr_serial and not StringValidator.is_urlsafe(csr_serial):
            exc_msg = 'Invalid serial number in CSR.'
            raise OnboardingError(exc_msg)
        if device.device_serial_number and csr_serial and device.device_serial_number != csr_serial:
            exc_msg = 'CSR serial number does not match device serial number.'
            raise OnboardingError(exc_msg)
        serial_no = device.device_serial_number or csr_serial
        device.device_serial_number = serial_no

        return CryptoBackend._sign_ldevid(csr.public_key(), device).public_bytes(serialization.Encoding.PEM)

    # @staticmethod
    # def get_cert_chain(device: Device) -> bytes:
    #     """Returns the certificate chain of the onboarding CA.
    #
    #     Returns: The certificate chain as bytes in PEM format.
    #
    #     Raises:
    #         OnboardingError: If the onboarding CA is not configured or not available.
    #     """
    #     ca_certificate = CryptoBackend._get_ca(device)
    #
    #     return ca_certificate.get_cert_chain_as_crypto()

    @staticmethod
    def _gen_private_key() -> PrivateKeyTypes:
        """Generates a keypair for the device.

        Returns: The keypair as PrivateKeyType.
        """
        # TODO (Air): Need to add configurable key type and size here
        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        return private_key

    @staticmethod
    def gen_keypair_and_ldevid(device: Device) -> bytes:
        """Generates a keypair and LDevID certificate for the device.

        Returns: The keypair and LDevID certificate as bytes in PEM format.

        Raises:
            OnboardingError: If the keypair generation or LDevID signing fails.
        """
        private_key = CryptoBackend._gen_private_key()

        ldevid = CryptoBackend._sign_ldevid(private_key.public_key(), device)

        ca_certificate = CryptoBackend._get_ca(device)
        ca_cert = ca_certificate.get_cert_as_crypto()

        pkcs12 = serialization.pkcs12.serialize_key_and_certificates(
            name=device.device_serial_number.encode(),
            key=private_key,
            cert=ldevid,
            cas=[ca_cert],
            encryption_algorithm=NoEncryption()
        )

        return pkcs12
