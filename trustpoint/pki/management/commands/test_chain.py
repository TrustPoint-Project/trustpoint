"""A."""


from __future__ import annotations

from pathlib import Path

from django.core.management import BaseCommand
from pki.models import Certificate, TrustStore
from random import shuffle
from cryptography import x509


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Just some stuff for manual testing.'

    def handle(self, *args, **kwargs) -> None:
        base_path = Path(__file__).parent.parent.parent.parent.parent.resolve()
        path = base_path / Path('tests/data/certs')

        with open(path / 'trust-store.pem', 'rb') as f:
            certs = x509.load_pem_x509_certificates(f.read())

        shuffle(certs)
        TrustStore.save_trust_store(unique_name='my_unique_name', trust_store=certs)

        print('\nDONE\n')
