"""A."""


from __future__ import annotations

from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from itertools import product

from django.core.management import BaseCommand
from pki.models import Certificate

from . import Algorithm


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Just some stuff for manual testing.'

    def handle(self, *args, **kwargs) -> None:
        base_path = Path(__file__).parent.parent.parent.parent.parent.resolve()
        path = base_path / Path('tests/data/certs')

        with open(path / Path('rsa4096-chain.pem'), 'rb') as f:
            rsa4096_chain = x509.load_pem_x509_certificates(f.read())
        with open(path / Path('rsa4096-ee-key.pem'), 'rb') as f:
            rsa4096_ee_key = serialization.load_pem_private_key(f.read(), password=None)

            print(rsa4096_chain)
            cert = Certificate.save_certificate_chain_and_key(certs=rsa4096_chain, priv_key=rsa4096_ee_key)

    print('\nDONE\n')
