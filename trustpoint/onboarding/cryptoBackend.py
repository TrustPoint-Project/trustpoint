"""This module provides cryptographic operations for use during the onboarding process.

This implementation is in testing stage and shall not be regarded as secure.
TODO sign_ldevid is Dragons with Lasers in central Berlin levels of a security risk TODO"""

import hashlib
import hmac
from cryptography import x509
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from devices.models import Device

from django.core.files.base import ContentFile

from pki.models import IssuingCa


class CryptoBackend:
    """Provides cryptographic operations for use during the onboarding process."""

    def pbkdf2_hmac_sha256(hexpass, hexsalt, message=b'', iterations=1000000, dklen=32):
        """Calculates the HMAC signature of the trust store.

        Returns:
            HMAC_SHA256(PBKDF2_SHA256(hexpass, hexsalt, iterations, dklen), message)
        """
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass, 'utf-8'), bytes(hexsalt, 'utf-8'), iterations, dklen)
        h = hmac.new(pkey, message, hashlib.sha256)
        return h.hexdigest()

    def get_trust_store():
        """Returns the trust store.

        TODO: Make location and included certificates configurable and verify that they are valid

        Returns:
            PEM string of the trust store (currently just a single HTTPS server certificate for testing purposes).

        Raises:
            FileNotFoundError: If the trust store file is not found.
        """

        with open('../tests/data/x509/https_server.crt', 'r') as certfile:
            return certfile.read()

    def sign_ldevid(csr_str: str, device: Device):
        """Signs a certificate signing request (CSR) with the onboarding CA.

        Args:
            csr_str: The certificate signing request as a string in PEM format.
            device: The Device to associate the signed certificate with.

        Returns: The signed certificate as a string in PEM format.

        Raises:
            Exception: If the onboarding CA is not configured or not available.
        """

        csr = x509.load_pem_x509_csr(csr_str)

        # TODO: DB query pending implementation of Endpoint profiles
        # TODO TODO TODO

        signingCa = IssuingCa.objects.filter(unique_name__contains='onboarding').first() # TODO select CA based on endpoint profile

        if not signingCa:
            raise Exception('No CA configured for onboarding. For testing, use a CA that has "onboarding" in its name.')
        
        if not signingCa.p12 or not signingCa.p12.path:
            raise Exception('CA is not associated with a .p12 file.')
        
        with open(signingCa.p12.path, 'rb') as cafile:
            ca_p12 = serialization.pkcs12.load_key_and_certificates(
                cafile.read(), b''
            )  # TODO (get password here if .p12 stored in media is password-protected)
            private_ca_key = ca_p12[0]
            ca_cert = ca_p12[1]

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
                # TODO configurable validity period
                datetime.now(timezone.utc) + timedelta(days=365)
                # Sign our certificate with our private key
            )
            .sign(private_ca_key, hashes.SHA256())
        )

        device.serial_number = cert.serial_number
        device.certificate = ContentFile(cert.public_bytes(serialization.Encoding.PEM), name='ldevid.pem')
        device.save()  # need to keep track of the device once we send out a cert, even if onboarding fails afterwards, TODO but do it here?

        return cert.public_bytes(serialization.Encoding.PEM)

    def get_cert_chain():
        """Returns the certificate chain of the onboarding CA.
        
        Returns: The certificate chain as a string in PEM format.
        
        Raises:
            Exception: If the onboarding CA is not configured or not available.
        """

        signingCa = IssuingCa.objects.filter(unique_name__contains='onboarding').first() # TODO select CA based on endpoint profile

        if not signingCa:
            raise Exception('No CA configured for onboarding. For testing, use a CA that has "onboarding" in its name.')
        
        if not signingCa.p12 or not signingCa.p12.path:
            raise Exception('CA is not associated with a .p12 file.')

        with open(signingCa.p12.path, 'rb') as cafile:
            ca_p12 = serialization.pkcs12.load_key_and_certificates(
                cafile.read(), b''
            )  # TODO (get password here if .p12 stored in media is password-protected)
            ca_cert = ca_p12[1]

        return ca_cert.public_bytes(serialization.Encoding.PEM)
