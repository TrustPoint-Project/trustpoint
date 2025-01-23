"""Initializer for Trust Store objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ValidationError
from django.db import transaction
from pki.models.certificate import CertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel

if TYPE_CHECKING:
    from typing import Union

    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


__all__ = [
    'TrustStoreInitializer'
]


class TrustStoreInitializer:
    """Handles the initialization and saving of trust stores, including certificates."""
    _unique_name: str
    _trust_store: list[x509.Certificate]
    _cert_model_class: type(CertificateModel) = CertificateModel
    _trust_store_model_class: type(TruststoreModel) = TruststoreModel
    _trust_store_order_model_class: type(TruststoreOrderModel) = TruststoreOrderModel

    def __init__(self, unique_name: str, intended_usage: int, trust_store: bytes | list[x509.Certificate]) -> None:
        """Initializes the TrustStoreInitializer.

        Args:
            unique_name (str): The unique name for the trust store.
            intended_usage (int): The intended usage of the trust store, which specifies how the certificates in
            the store are to be used (e.g., for signing, encryption, etc.).
            trust_store (bytes | list[x509.Certificate]): PEM data or list of certificates.

        Raises:
            ValidationError: If the PEM data is invalid or cannot be processed.
        """
        if isinstance(trust_store, bytes):
            trust_store = self._process_pem_file(trust_store)

        self._unique_name = unique_name
        self._intended_usage = intended_usage
        self._trust_store = trust_store

    @staticmethod
    def _process_pem_file(pem_data: bytes) -> list[x509.Certificate]:
        """Cleans and processes a PEM file, removing invalid metadata and validating certificates.

        Args:
            pem_data (bytes): Raw PEM data.

        Returns:
            list[x509.Certificate]: A list of x509.Certificate objects.

        Raises:
            ValidationError: If the PEM file contains invalid or malformed certificates.
        """
        try:
            pem_str = pem_data.decode('utf-8')
        except UnicodeDecodeError as decode_error:
            error_message = 'The provided PEM file is not UTF-8 encoded.'
            raise ValidationError(error_message) from decode_error

        # Clean the PEM file by removing non-certificate lines
        cleaned_lines = []
        inside_certificate = False

        for line in pem_str.splitlines():
            if '-----BEGIN CERTIFICATE-----' in line:
                inside_certificate = True
            if inside_certificate:
                cleaned_lines.append(line)
            if '-----END CERTIFICATE-----' in line:
                inside_certificate = False

        cleaned_pem = '\n'.join(cleaned_lines).encode('utf-8')

        try:
            certificates = x509.load_pem_x509_certificates(cleaned_pem)
        except ValueError as load_error:
            error_message = f'Unable to process the PEM file: {load_error}'
            raise ValidationError(error_message) from load_error

        return certificates

    @transaction.atomic
    def save(self) -> TruststoreModel:
        """Saves the trust store and associated certificates to the database.

        Returns:
            TruststoreModel: The saved trust store instance.
        """
        saved_certs = []

        for certificate in self._trust_store:
            sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()
            try:
                saved_certs.append(CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint))
            except CertificateModel.DoesNotExist:
                saved_certs.append(self._cert_model_class.save_certificate(certificate))

        trust_store_model = self._trust_store_model_class(unique_name=self._unique_name,
                                                          intended_usage=self._intended_usage)
        trust_store_model.save()

        for number, certificate in enumerate(saved_certs):
            _trust_store_order_model = self._trust_store_order_model_class()
            _trust_store_order_model.order = number
            _trust_store_order_model.certificate = certificate
            _trust_store_order_model.trust_store = trust_store_model
            _trust_store_order_model.save()

        return trust_store_model
