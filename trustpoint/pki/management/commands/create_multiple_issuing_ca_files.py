"""Something."""


from __future__ import annotations

from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from .base_commands import Command

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Command(Command):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:

        root_1, root_1_key = self.create_root_ca('Root CA')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')
        issuing_2, issuing_2_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA B')
        issuing_3, issuing_3_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA C')

        self.store_issuing_ca(issuing_1, [root_1], issuing_1_key, 'A.p12')
        self.store_issuing_ca(issuing_2, [root_1], issuing_2_key, 'B.p12')
        self.store_issuing_ca(issuing_3, [root_1], issuing_3_key, 'C.p12')

        self.store_issuing_ca(root_1, [], root_1_key, 'D.p12')
