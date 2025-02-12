from __future__ import annotations

import random
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for creating a Root CA with a 3-level intermediate CA hierarchy."""

    help = 'Creates a Root CA with three levels of Intermediate CAs and issues end-entity certificates.'

    def handle(self, *args, **kwargs) -> None:
        key_usage_extension = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            decipher_only=False,
            encipher_only=False
        )

        root_ca, root_key = self.create_root_ca('root_ca')

        intermediate_1, intermediate_1_key = self.create_issuing_ca(
            root_key, 'root_ca', 'intermediate_1', validity_days=365
        )

        intermediate_2, intermediate_2_key = self.create_issuing_ca(
            intermediate_1_key, 'intermediate_1', 'intermediate_2', validity_days=365
        )

        intermediate_3, intermediate_3_key = self.create_issuing_ca(
            intermediate_2_key, 'intermediate_2', 'intermediate_3', validity_days=365
        )

        self.store_issuing_ca(intermediate_1, [root_ca], intermediate_1_key, 'intermediate_1.p12')
        self.save_issuing_ca(intermediate_1, root_ca, [root_ca], intermediate_1_key, 'intermediate_1')

        self.store_issuing_ca(intermediate_2, [intermediate_1, root_ca], intermediate_2_key, 'intermediate_2.p12')
        self.save_issuing_ca(intermediate_2, intermediate_1, [intermediate_1, root_ca], intermediate_2_key,
                             'intermediate_2')

        self.store_issuing_ca(intermediate_3, [intermediate_2, intermediate_1, root_ca], intermediate_3_key,
                              'intermediate_3.p12')
        self.save_issuing_ca(intermediate_3, intermediate_2, [intermediate_2, intermediate_1, root_ca],
                             intermediate_3_key, 'intermediate_3')

        ee_certs = {}
        ee_keys = {}
        for i in range(0, 100):
            random_integer = random.randint(20, 80)
            sign = random.choice([1, -1])
            validity_days = random_integer * sign

            ee, key = self.create_ee(
                issuer_private_key=intermediate_3_key,
                issuer_cn='intermediate_3',
                subject_cn=f'EE {i}',
                key_usage_extension=key_usage_extension,
                validity_days=validity_days
            )
            ee_certs[f'ee{i}'] = ee
            ee_keys[f'key{i}'] = key

        self.store_ee_certs(ee_certs)
        self.store_ee_keys(ee_keys)
        self.save_ee_certs(ee_certs)

        self.create_csr(10)
