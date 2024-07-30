from __future__ import annotations

from abc import ABC, abstractmethod
from .serializer import CertificateSerializer, CertificateChainSerializer, PublicKeySerializer
# from devices.models import Device


from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Union
    from .models import CertificateModel, IssuingCaModel
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
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

    def __init__(self, issuing_ca_model: IssuingCaModel) -> None:
        self._issuing_ca_model = issuing_ca_model

    # def issue_ldevid(self, device: Device):
    #     pass

    # def issue_certificate(self, *args, **kwargs) -> CertificateModel:
    #     pass
    #
    # def sign_crl(self, *args, **kwargs) -> Any:
    #     pass
