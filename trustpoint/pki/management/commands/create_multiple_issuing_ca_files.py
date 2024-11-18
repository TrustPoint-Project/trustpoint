"""Something."""


from __future__ import annotations

from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:

        root_1, root_1_key = self.create_root_ca('Root CA')
        _, _ = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')
        _, _ = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA B')
        _, _ = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA C')
