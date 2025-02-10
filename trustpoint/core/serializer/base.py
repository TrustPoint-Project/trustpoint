"""The base module provides abstract base Serializer classes."""

import abc
from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.
    """

    @abc.abstractmethod
    def serialize(self) -> bytes:
        """The default serialization method."""
