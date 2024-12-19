"""The base module provides abstract base Serializer classes."""

import abc
from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Serializer(abc.ABC):
    """Abstract Base Class for all Serializer classes.

    Warnings:
        Serializer classes do not include any type of validation.
        They are merely converting between formats.
    """

    @abc.abstractmethod
    def serialize(self) -> bytes:
        """The default serialization method."""
