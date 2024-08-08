from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod
from enum import Enum


from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    Operation = Union['EstOperation']
    from .models import DomainModel


class CertificateRequestValidator:
    pass


class EstOperation(Enum):

    SIMPLE_ENROLL = 'simple_enroll'


class PkiProtocol(Enum):

    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'


class PkiMessage(ABC):
    # TODO: Validators
    _private_key: None | PrivateKey = None
    _operation: None | Operation
    _domain: DomainModel
    _protocol: PkiProtocol

    def validate(self) -> None:
        pass

    def generate_private_key(self, force: bool = False) -> None:
        pass


class PkiRequestMessage(PkiMessage):
    pass


class PkiEstRequestMessage(PkiRequestMessage):
    _validator: None
