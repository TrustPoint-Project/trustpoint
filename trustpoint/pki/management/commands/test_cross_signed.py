"""Something."""


from __future__ import annotations


from django.core.management import BaseCommand

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID
import datetime

from pki.models import CertificateModel


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    @staticmethod
    def create_root_ca(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(365, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    @staticmethod
    def create_issuing_ca(
            issuer_private_key: rsa.RSAPrivateKey,
            issuer_cn: str, subject_cn,
            private_key: None | rsa.RSAPrivateKey = None) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(365, 0, 0)
        if private_key is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    @staticmethod
    def create_ee(
            issuer_private_key: rsa.RSAPrivateKey,
            issuer_cn: str, subject_cn) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(365, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    def handle(self, *args, **kwargs) -> None:

        root_1, root_1_key = self.create_root_ca('Root CA A')
        root_2, root_2_key = self.create_root_ca('Root CA B')

        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA A', 'Issuing CA')
        issuing_2, issuing_2_key = self.create_issuing_ca(
            root_2_key, 'Root CA B', 'Issuing CA', issuing_1_key)

        ee_1, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE A1')
        ee_2, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE A2')
        ee_3, _ = self.create_ee(issuing_2_key, 'Issuing CA', 'EE B1')
        ee_4, _ = self.create_ee(issuing_2_key, 'Issuing CA', 'EE B1')

        CertificateModel.save_certificate(root_1)
        CertificateModel.save_certificate(root_2)
        CertificateModel.save_certificate(issuing_1)
        CertificateModel.save_certificate(issuing_2)
        CertificateModel.save_certificate(ee_1)
        CertificateModel.save_certificate(ee_2)
        CertificateModel.save_certificate(ee_3)
        CertificateModel.save_certificate(ee_4)

