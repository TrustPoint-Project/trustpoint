"""Django management command for adding issuing CA test data."""


from __future__ import annotations

from typing import Union

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Adds a Root CA and three issuing CAs to the database.'

    def handle(self, *args, **kwargs) -> None:

        root_1, root_1_key = self.create_root_ca('Root CA')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')
        issuing_2, issuing_2_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA B')
        issuing_3, issuing_3_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA C')

        self.save_issuing_ca(
            issuing_ca_cert=issuing_1,
            root_ca_cert=root_1,
            private_key=issuing_1_key,
            chain=[],
            unique_name='issuing-ca-a')
        self.save_issuing_ca(
            issuing_ca_cert=issuing_2,
            root_ca_cert=root_1,
            private_key=issuing_2_key,
            chain=[],
            unique_name='issuing-ca-b')
        self.save_issuing_ca(
            issuing_ca_cert=issuing_3,
            root_ca_cert=root_1,
            private_key=issuing_3_key,
            chain=[],
            unique_name='issuing-ca-c')
