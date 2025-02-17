"""Django management command for adding issuing CA test data."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from .base_commands import CertificateCreationCommandMixin


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Adds a Root CA and three issuing CAs to the database.'

    def handle(self, *_args: dict, **_kwargs: dict) -> None:
        """Adds a Root CA and three issuing CAs to the database."""
        root_1, root_1_key = self.create_root_ca('Root CA')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA A')
        issuing_2, issuing_2_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA B')
        issuing_3, issuing_3_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA C')

        self.save_issuing_ca(
            issuing_ca_cert=issuing_1,
            private_key=issuing_1_key,
            chain=[root_1],
            unique_name='issuing-ca-a')
        self.save_issuing_ca(
            issuing_ca_cert=issuing_2,
            private_key=issuing_2_key,
            chain=[root_1],
            unique_name='issuing-ca-b')
        self.save_issuing_ca(
            issuing_ca_cert=issuing_3,
            private_key=issuing_3_key,
            chain=[root_1],
            unique_name='issuing-ca-c')
