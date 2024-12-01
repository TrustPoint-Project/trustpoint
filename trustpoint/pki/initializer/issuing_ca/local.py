"""Code common to all local CAs."""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING

from django.db import transaction
from django.utils.translation import gettext_lazy as _

from pki.models import CertificateChainOrderModel, CertificateModel, IssuingCaModel
from core.serializer import CertificateCollectionSerializer, CredentialSerializer, PrivateKeySerializer
from pki.util import Sha256Fingerprint

from . import IssuingCaInitializer, IssuingCaInitializerError

if TYPE_CHECKING:
    from typing import Union

    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]

log = logging.getLogger('tp.pki.initializer')


class LocalIssuingCaInitializerError(IssuingCaInitializerError):
    """Base class for all exceptions specific to local CA initialization."""


class InternalServerError(LocalIssuingCaInitializerError):
    """Raised if an unexpected error occurred.

    E.g. is raised, if .initialize() is not called before .save()
    """

    def __init__(self, message: None | str = None) -> None:
        """Adds a default message if none is provided."""
        if message:
            super().__init__(message=message)
        else:
            super().__init__(message=_(
                'An unexpected internal server error occurred during CA initialization.'
                'Please contact the Trustpoint support.'))


class IssuingCaAlreadyExistsError(LocalIssuingCaInitializerError):
    """Raised if an Issuing CA already exists for a corresponding Issuing CA certificate."""

    def __init__(self, name: str) -> None:
        super().__init__(message=_(f'Issuing CA already exists with unique name: {name}.'))


class LocalIssuingCaInitializer(IssuingCaInitializer, abc.ABC):
    """Abstract base class for the local issuing CA initializer."""

    _credential_serializer: CredentialSerializer
    _private_key_serializer: PrivateKeySerializer
    _certificate_collection_serializer: CertificateCollectionSerializer

    _credential_serializer_class: type[CredentialSerializer] = CredentialSerializer

    _cert_model_class: type[CertificateModel] = CertificateModel
    _issuing_ca_model_class: type[IssuingCaModel] = IssuingCaModel
    _cert_chain_order_model_class: type[CertificateChainOrderModel] = CertificateChainOrderModel

    @transaction.atomic
    def save(self) -> None:
        """Saves the initialized Issuing CA in the database.

        Raises:
            InternalServerError: If the Issuing CA was not yet initialized or some other unexpected error occurred.
        """
        if not self._is_initialized:
            raise InternalServerError

        try:
            issuing_ca_certificate = self._credential_serializer.credential_certificate.as_crypto()

            try:
                saved_certs = [self._cert_model_class.save_certificate(issuing_ca_certificate)]
            except ValueError:

                cert_model = self._cert_model_class.objects.get(
                    sha256_fingerprint=Sha256Fingerprint.get_fingerprint_hex_str(issuing_ca_certificate))

                if hasattr(cert_model, 'issuing_ca_model'):
                    raise IssuingCaAlreadyExistsError(name=cert_model.issuing_ca_model.unique_name)

                saved_certs = [cert_model]

            if (self._credential_serializer.additional_certificates):
                for certificate in self._credential_serializer.additional_certificates.crypto_iterator():
                    saved_certs.append(self._cert_model_class.save_certificate(certificate, exist_ok=True))

            issuing_ca_model = self._issuing_ca_model_class(
                unique_name=self._unique_name,
                private_key_pem=self._credential_serializer.credential_private_key.as_pkcs1_pem(None).decode('utf-8')
            )

            if hasattr(self, '_ca_localization'):
                issuing_ca_model.ca_localization = self._ca_localization

            issuing_ca_model.issuing_ca_certificate = saved_certs[0]
            issuing_ca_model.root_ca_certificate = saved_certs[-1]
            issuing_ca_model.save()

            for number, certificate in enumerate(saved_certs[1:-1]):
                cert_chain_order_model = self._cert_chain_order_model_class()
                cert_chain_order_model.order = number
                cert_chain_order_model.certificate = certificate
                cert_chain_order_model.issuing_ca = issuing_ca_model
                cert_chain_order_model.save()
        except Exception as exception:
            log.exception(exception)
            raise InternalServerError from exception
