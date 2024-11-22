"""This module provides cryptographic operations for use during the onboarding process.

This implementation is in testing stage and shall not be regarded as secure.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.db import transaction
from pki import CertificateTypes, TemplateName
from pki.oid import NameOid
from pki.models import CertificateModel
from pki.util.keys import DigitalSignature
from pki.pki.request.handler.factory import CaRequestHandlerFactory
from pki.pki.request.message.rest import PkiRestCsrRequestMessage, PkiRestPkcs12RequestMessage

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from devices.models import Device

PBKDF2_ITERATIONS = 1000000
PBKDF2_DKLEN = 32

log = logging.getLogger('tp.onboarding')

CONTAINER_HTTPS_SERVER_CERT_PATH = Path('/etc/ssl/certs/apache-selfsigned.crt')
HTTPS_SERVER_CERT_PATH = Path(__file__).parent.parent.parent / 'tests/data/x509/https_server.crt'

class OnboardingError(Exception):
    """Exception raised for errors in the onboarding process."""

    def __init__(self, message: str = 'An error occurred during onboarding.') -> None:
        """Initializes a new OnboardingError with a given message."""
        self.message = message
        super().__init__(self.message)
        log.exception(self.message, exc_info=True)

class VerificationError(Exception):
    """Exception raised for errors in signature verification."""

    def __init__(self, message: str = 'An error occurred during signature verification.') -> None:
        """Initializes a new VerificationError with a given message."""
        self.message = message
        super().__init__(self.message)
        log.exception(self.message, exc_info=True)

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
    def get_server_tls_cert() -> str:
        """Returns the TLS certificate used by the Trustpoint server.

        TODO: Make location and included certificates configurable and verify that they are valid

        Returns:
            PEM string of the TLS  server certificate.

        Raises:
            FileNotFoundError: If the TLS certificate file is not found.
        """
        if CONTAINER_HTTPS_SERVER_CERT_PATH.exists() and CONTAINER_HTTPS_SERVER_CERT_PATH.is_file():
            with CONTAINER_HTTPS_SERVER_CERT_PATH.open() as certfile:
                return certfile.read()

        with HTTPS_SERVER_CERT_PATH.open() as certfile:
            return certfile.read()

    @staticmethod
    def get_trust_store() -> str:
        """Returns the trust store.

        TODO: Make location and included certificates configurable and verify that they are valid

        Returns:
            PEM string of the trust store (currently just a single HTTPS server certificate for testing purposes).

        Raises:
            FileNotFoundError: If the trust store file is not found.
        """
        return CryptoBackend.get_server_tls_cert()

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
        log.debug('Accessing CA for device %s', device.device_name)
        if not device.domain:
            msg = 'No domain profile configured for device.'
            raise OnboardingError(msg)

        try:
            signing_ca = device.domain.issuing_ca
        except AttributeError as e:
            msg = 'Could not obtain issuing CA from domain profile.'
            raise OnboardingError(msg) from e

        if not signing_ca:
            msg = 'No CA configured in domain profile.'
            raise OnboardingError(msg)

        if not signing_ca.issuing_ca_certificate:
            msg = 'CA does not have issuing CA certificate.'
            raise OnboardingError(msg)

        return signing_ca.issuing_ca_certificate

    @staticmethod
    @transaction.atomic
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
        log.debug('Received CSR for device %s', device.device_name)

        log.debug('Issuing LDevID for device %s', device.device_name)

        pki_request = PkiRestCsrRequestMessage(
            domain_model=device.domain, raw_content=csr_pem,
            serial_number_expected=device.device_serial_number, device_name=device.device_name
        )
        request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
        pki_response = request_handler.process_request()
        cert_model = pki_response.cert_model

        if not isinstance(cert_model, CertificateModel):
            exc_msg = 'PKI response error: not a certificate: %s' % cert_model
            raise OnboardingError(exc_msg)

        try: # Extract device serial number from LDevID subject
            sn = cert_model.get_subject_attributes_for_oid(NameOid.SERIAL_NUMBER)[0].value
            device.device_serial_number = sn
        except IndexError as e:
            log.warning(f'Device serial empty for device {device.device_name}.'
                        ' No serial number found in issued LDevID!')

        device.save_certificate(
            certificate=cert_model,
            certificate_type=CertificateTypes.LDEVID,
            domain=device.domain,
            template_name=TemplateName.GENERIC,
            protocol=device.onboarding_protocol
        )
        device.save()
        log.info('Issued and stored LDevID for device %s', device.device_name)

        return pki_response.raw_response

    @staticmethod
    def get_cert_chain(device: Device) -> bytes:
        """Returns the certificate chain of the onboarding CA.

        Returns: The certificate chain as bytes in PEM format.

        Raises:
            OnboardingError: If the onboarding CA is not configured or not available.
        """
        ca_certificate = CryptoBackend._get_ca(device)

        return ca_certificate.get_certificate_chain_serializers()[0].as_pem()

    @staticmethod
    def _gen_private_key() -> PrivateKeyTypes:
        """Generates a keypair for the device.

        Returns: The keypair as PrivateKeyType.
        """
        log.debug('Generating new private key for manual device')
        # TODO (Air): Need to add configurable key type and size here
        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        return private_key

    @staticmethod
    @transaction.atomic
    def gen_keypair_and_ldevid(device: Device) -> bytes:
        """Generates a keypair and LDevID certificate for the device.

        Returns: The keypair and LDevID certificate as PKCS12 bytes.

        Raises:
            OnboardingError: If the keypair generation or LDevID signing fails.
        """
        log.debug('Generating PKCS12 for device %s', device.device_name)

        if not device.device_serial_number:
            exc_msg = f'No serial number provided in CSR for device {device.device_name}'
            raise OnboardingError(exc_msg)
        serial_no = device.device_serial_number

        log.debug('Issuing LDevID for device %s', device.device_name)

        pki_request = PkiRestPkcs12RequestMessage(
            domain_model=device.domain, serial_number=serial_no, device_name=device.device_name
        )
        request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
        pki_response = request_handler.process_request()
        cert_model = pki_response.cert_model

        if not isinstance(cert_model, CertificateModel):
            exc_msg = 'PKI response error: not a certificate: %s' % cert_model
            raise OnboardingError(exc_msg)

        device.save_certificate(
            certificate=cert_model,
            certificate_type=CertificateTypes.LDEVID,
            domain=device.domain,
            template_name=TemplateName.GENERIC,
            protocol=device.onboarding_protocol
        )
        device.save()
        log.info('Issued and stored LDevID for device %s', device.device_name)
        return pki_response.raw_response

    @staticmethod
    def get_nonce(nbytes: int = 16) -> str:
        """Generates a new nonce for use in the onboarding process."""
        return secrets.token_urlsafe(nbytes)


    @staticmethod
    def verify_signature(message: bytes, cert: bytes, signature: bytes) -> None:
        """Verifies the message was signed by the cert provided (e.g. IDevID).
        
        Raises: VerificationError if certificate could not be loaded.
                InvalidSignature if signature does not match.
        """

        log.debug('Verifying (client) signature...')
        hash_ = hashes.Hash(hashes.SHA256())
        hash_.update(message)
        log.debug(f'SHA-256 hash of message: {hash_.finalize().hex()}')

        try:
            cert = x509.load_pem_x509_certificate(cert)
            signer_public_key = cert.public_key()
            print(f'Signer public key: {signer_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}')
        except Exception as e:
            exc_msg = 'Failed to load public key from certificate.'
            raise VerificationError(exc_msg) from e
        
        # print(f'signature: {signature}')
        DigitalSignature.verify(signature=signature, data=message, public_key=signer_public_key)
