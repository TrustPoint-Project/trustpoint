"""Something."""


from __future__ import annotations

import datetime
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:
        key_usage_extension = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            decipher_only=False,
            encipher_only=False
        )

        root_1, root_1_key = self.create_root_ca('Root CA')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA')

        self.store_issuing_ca(issuing_1, [root_1], issuing_1_key, 'issuing_ca.p12')
        self.save_issuing_ca(issuing_1, root_1, [], issuing_1_key)

        ee_certs = {}
        ee_keys = {}
        for i in range(0, 100):
            ee, key = self.create_ee(
                issuer_private_key=issuing_1_key,
                issuer_cn='Issuing CA',
                subject_cn=f'EE {i}',
                key_usage_extension=key_usage_extension
            )
            ee_certs[f'ee{i}'] = ee
            ee_keys[f'key{i}'] = key

        self.store_ee_certs(ee_certs)
        self.store_ee_keys(ee_keys)
        self.save_ee_certs(ee_certs)

        self.create_csr(10)
