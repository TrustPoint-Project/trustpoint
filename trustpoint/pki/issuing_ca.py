from __future__ import annotations

from abc import ABC, abstractmethod
from .serializer import CertificateSerializer, CertificateCollectionSerializer, PublicKeySerializer, \
    PrivateKeySerializer
# from devices.models import Device


from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Union
    from .models import CertificateModel, IssuingCaModel
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


class IssuingCa(ABC):
    _issuing_ca_model: IssuingCaModel

    # @abstractmethod
    # def issue_ldevid(self, device: Device):
    #     pass

    # @abstractmethod
    # def issue_certificate(self, *args, **kwargs) -> CertificateModel:
    #     pass
    #
    # @abstractmethod
    # def sign_crl(self, *args, **kwargs) -> Any:
    #     pass


class UnprotectedLocalIssuingCa(IssuingCa):

    _issuing_ca_model: IssuingCaModel
    _private_key_serializer: PrivateKeySerializer

    def __init__(self, issuing_ca_model: IssuingCaModel) -> None:
        self._issuing_ca_model = issuing_ca_model
        self._private_key_serializer = self._get_private_key_serializer()

    def _get_private_key_serializer(self) -> PrivateKeySerializer:
        return PrivateKeySerializer.from_string(self._issuing_ca_model.private_key_pem)

    def generate_crl(self, crl_builder: x509.CertificateRevocationListBuilder) -> x509.CertificateRevocationList:
        # TODO: this should not take an crl_builder object, but instead get the crl information required from the
        # TODO: issuing ca model / crl model and sign the crl as below.
        return crl_builder.sign(private_key=self._private_key_serializer.as_crypto(), algorithm=hashes.SHA256())

    # def issue_ldevid(self, device: Device):
    #     pass

    # def issue_certificate(self, *args, **kwargs) -> CertificateModel:
    #     pass
    #
    # def sign_crl(self, *args, **kwargs) -> Any:
    #     pass
