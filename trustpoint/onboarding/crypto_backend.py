"""This module provides cryptographic operations for use during the onboarding process.

This implementation is in testing stage and shall not be regarded as secure.
TODO sign_ldevid is Dragons with Lasers in central Berlin levels of a security risk TODO
"""
from __future__ import annotations
from typing import TYPE_CHECKING

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from devices.models import Device
from django.core.files.base import ContentFile
from pki.models import IssuingCa

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from cryptography.x509 import Certificate

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
            iterations: int = 1000000,
            dklen: int = 32) -> str:
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
        with Path('../tests/data/x509/https_server4.crt').open() as certfile:
            return certfile.read()
        
    @staticmethod
    def _get_ca_p12(device: Device) -> tuple[PrivateKeyTypes | None, Certificate | None, list[Certificate]]:
        """Returns the CA private key, certificate and the CA certificate chain for a given device.

        Args:
            device (Device):
                The Device, whose endpoint profile to obtain the CA from.

        Returns:
            tuple[PrivateKeyTypes | None, Certificate | None, list[Certificate]]:
                The CA private key, certificate and the CA certificate chain.
        """
        try:
            signing_ca = device.endpoint_profile.issuing_ca
        except AttributeError:
            msg = 'Could not obtain issuing CA from endpoint profile.'
            raise OnboardingError(msg)

        if not signing_ca:
            msg = 'No CA configured in endpoint profile.'
            raise OnboardingError(msg)

        if not signing_ca.p12 or not signing_ca.p12.path:
            msg = 'CA is not associated with a .p12 file.'
            raise OnboardingError(msg)

        with Path.open(signing_ca.p12.path, 'rb') as ca_file:
            ca_p12 = pkcs12.load_key_and_certificates(
                ca_file.read(), b''  # TODO(Air): get password here if .p12 stored in media is password-protected
            )
            private_ca_key = ca_p12[0]
            ca_cert = ca_p12[1]
            ca_chain = ca_p12[2:]

        return private_ca_key, ca_cert, ca_chain

    @staticmethod
    def sign_ldevid(csr_str: bytes, device: Device) -> bytes:
        """Signs a certificate signing request (CSR) with the onboarding CA.

        Args:
            csr_str (bytes):
                The certificate signing request as a string in PEM format.
            device (Device):
                The Device to associate the signed certificate with.

        Returns: The signed certificate as a string in PEM format.

        Raises:
            OnboardingError: If the onboarding CA is not configured or not available.
        """
        csr = x509.load_pem_x509_csr(csr_str)

        # TODO(Air): Only sign if a serial number was provided either in device or in the CSR

        private_ca_key, ca_cert, _ = CryptoBackend._get_ca_p12(device)

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.now(timezone.utc) - timedelta(hours=1)  # backdate a bit in case of client clock skew
            )
            .not_valid_after(
                # TODO(Air): configurable validity period
                datetime.now(timezone.utc) + timedelta(days=365)
                # Sign our certificate with our private key
            )
            .sign(private_ca_key, hashes.SHA256())
        )

        device.ldevid = ContentFile(cert.public_bytes(serialization.Encoding.PEM), name='ldevid.pem')
        # need to keep track of the device once we send out a cert, even if onboarding fails afterwards
        # TODO(Air): but do it here?
        device.save()

        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def get_cert_chain(device: Device) -> bytes:
        """Returns the certificate chain of the onboarding CA.

        Returns: The certificate chain as bytes in PEM format.

        Raises:
            OnboardingError: If the onboarding CA is not configured or not available.
        """
        _, ca_cert, _ = CryptoBackend._get_ca_p12(device)

        return ca_cert.public_bytes(serialization.Encoding.PEM)
