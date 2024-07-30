from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod


from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class CertificateRequestValidator:
    pass


class CertificateRequest(ABC):
    _validator: CertificateRequestValidator
    _private_key: None | PrivateKey = None

    def validate(self) -> None:
        pass

    def generate_private_key(self, force: bool = False) -> None:
        pass


class LDevIdCertificateRequest(CertificateRequest):

    def __init__(self, validator: CertificateRequestValidator):
        pass
