from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec

from core.serializer import PrivateKeySerializer, CredentialSerializer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, ec

class DomainCredentialBuilder:
    """Constructs domain credentials for the onboarding processes implementing the builder pattern."""

    _issuing_ca_credential: None | CredentialSerializer = None
    _device_name: None | str = None
    _domain_name: None | str = None
    _device_serial_number: None | str = None

    def set_issuing_ca_credential(self, credential: CredentialSerializer) -> None:
        self._issuing_ca_credential = credential

    def set_device_name(self, device_name: str) -> None:
        self._device_name = device_name

    def set_device_serial_number(self, device_serial_number: str) -> None:
        self._device_serial_number = device_serial_number

    def set_domain_name(self, domain_name: str) -> None:
        self._domain_name = domain_name

    def _generate_domain_credential_private_key(self) -> PrivateKeySerializer:
        issuing_ca_private_key = self._issuing_ca_credential.credential_private_key.as_crypto()
        if isinstance(issuing_ca_private_key, rsa.RSAPrivateKey):
            key_size = issuing_ca_private_key.key_size
            return PrivateKeySerializer(
                rsa.generate_private_key(key_size=key_size, public_exponent=65537)
            )
        if isinstance(issuing_ca_private_key, ec.EllipticCurvePrivateKey):
            curve = issuing_ca_private_key.curve
            return PrivateKeySerializer(
                ec.generate_private_key(curve=curve)
            )
        raise ValueError('Cannot build the domain credential, unknown key type found.')

    def _get_hash_algorithm_from_issuing_ca_credential(self) -> hashes.SHA256 | hashes.SHA384:
        hash_algorithm = self._issuing_ca_credential.credential_certificate.as_crypto().signature_hash_algorithm
        if isinstance(hash_algorithm, hashes.SHA256):
            return hashes.SHA256()
        if isinstance(hash_algorithm, hashes.SHA384):
            return hashes.SHA384()
        raise ValueError('Cannot build the domain credential, unknown hash algorithm found.')

    def build(self) -> CredentialSerializer:
        if self._issuing_ca_credential is None:
            raise ValueError('Cannot build the domain credential, issuing ca credential is missing.')
        if self._domain_name is None:
            raise ValueError('Cannot build the domain credential, domain name is missing.')
        if self._device_serial_number is None:
            raise ValueError('Cannot build the domain credential, device serial number is missing.')

        domain_credential_private_key = self._generate_domain_credential_private_key()
        hash_algorithm = self._get_hash_algorithm_from_issuing_ca_credential()
        one_day = datetime.timedelta(1, 0, 0)

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Device Credential'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, f'trustpoint.{self._device_name}.{self._domain_name}.local'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, self._device_serial_number)
        ]))
        certificate_builder = certificate_builder.issuer_name(
            self._issuing_ca_credential.credential_certificate.as_crypto().subject)
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.now(datetime.UTC))
        certificate_builder = certificate_builder.not_valid_after(datetime.datetime.now(datetime.UTC) + (one_day * 365))
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.public_key(
            domain_credential_private_key.public_key_serializer.as_crypto())
        domain_certificate = certificate_builder.sign(
            private_key=domain_credential_private_key.as_crypto(),
            algorithm=hash_algorithm
        )

        return CredentialSerializer(
            (
                domain_credential_private_key,
                domain_certificate,
                [self._issuing_ca_credential.credential_certificate.as_crypto()] +
                self._issuing_ca_credential.additional_certificates.as_crypto()
            )
        )
