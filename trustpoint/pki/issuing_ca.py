from __future__ import annotations

import logging
from abc import ABC
from typing import TYPE_CHECKING

from cryptography import x509

from core.serializer import CertificateCollectionSerializer, PrivateKeySerializer

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from .models import CertificateModel, BaseCaModel
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    from core.serializer import CertificateSerializer, PublicKeySerializer


log = logging.getLogger('tp.pki')


class IssuingCa(ABC):
    _issuing_ca_model: BaseCaModel

    def get_issuing_ca_certificate(self) -> CertificateModel:
        return self._issuing_ca_model.get_issuing_ca_certificate()

    def get_issuing_ca_certificate_serializer(self) -> CertificateSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer()

    def get_issuing_ca_public_key_serializer(self) -> PublicKeySerializer:
        return self._issuing_ca_model.get_issuing_ca_public_key_serializer()

    def get_issuing_ca_certificate_chain(self) -> list[CertificateModel]:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain()

    def get_issuing_ca_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        return self._issuing_ca_model.get_issuing_ca_certificate_chain_serializer()

    @property
    def issuing_ca_model(self) -> BaseCaModel:
        return self._issuing_ca_model


class UnprotectedLocalIssuingCa(IssuingCa):

    _private_key: None | PrivateKey = None
    _builder: x509.CertificateRevocationListBuilder

    def __init__(self, issuing_ca_model: BaseCaModel, *args, **kwargs) -> None:
        """Initializes an UnprotectedLocalIssuingCa instance.

        Args:
            issuing_ca_model (BaseCaModel): The issuing CA model instance
            representing the CA
        """
        super().__init__(*args, **kwargs)
        self._issuing_ca_model = issuing_ca_model
        self._private_key_serializer = self._get_private_key_serializer()
        ca_serializer = self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto()
        log.debug('UnprotectedLocalIssuingCa initialized.')

    @property
    def issuer_name(self) -> x509.Name:
        # TODO: store issuer and subject bytes in DB
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto().issuer

    @property
    def subject_name(self) -> x509.Name:
        return self._issuing_ca_model.get_issuing_ca_certificate_serializer().as_crypto().subject

    @property
    def private_key(self) -> PrivateKey:
        if self._private_key is None:
            self._private_key = PrivateKeySerializer(self._issuing_ca_model.private_key_pem).as_crypto()
        return self._private_key

    def _get_private_key_serializer(self) -> PrivateKeySerializer:
        """Retrieves the private key serializer for the issuing CA.

        Returns:
            PrivateKeySerializer: A serializer instance for the CA's private key.
        """
        return PrivateKeySerializer(self._issuing_ca_model.private_key_pem)

    def get_ca_name(self) -> str:
        """Retrieves the unique name of the issuing CA.

        Returns:
            str: The unique name of the CA.
        """
        return self._issuing_ca_model.unique_name
