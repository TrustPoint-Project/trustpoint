"""Something."""


from __future__ import annotations


from django.core.management import BaseCommand

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    NoEncryption
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from pathlib import Path
import shutil

from pki.models import CertificateModel, IssuingCaModel


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

    @staticmethod
    def store_issuing_ca(
            issuing_ca_cert: x509.Certificate,
            chain: list[x509.Certificate],
            private_key: rsa.RSAPrivateKey) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_ca')
        issuing_ca_path = tests_data_path / Path('issuing_ca.p12')
        shutil.rmtree(tests_data_path, ignore_errors=True)
        tests_data_path.mkdir(exist_ok=True)

        print('\nSaving Issuing CA and Certificates\n')

        p12 = pkcs12.serialize_key_and_certificates(
            name=b'',
            key=private_key,
            cert=issuing_ca_cert,
            cas=chain,
            encryption_algorithm=BestAvailableEncryption(b"testing321"))

        with open(issuing_ca_path, 'wb') as f:
            f.write(p12)

        print(f'Issuing CA: {issuing_ca_path}')
        print(f'Issuing CA - Password: testing321\n')

    @staticmethod
    def save_issuing_ca(
            issuing_ca_cert: x509.Certificate,
            root_ca_cert: x509.Certificate,
            chain: list[x509.Certificate],
            private_key: rsa.RSAPrivateKey) -> None:
        issuing_ca_cert_model = CertificateModel.save_certificate(issuing_ca_cert)
        root_ca_cert_model = CertificateModel.save_certificate(root_ca_cert)

        intermediate_ca_certs = []
        for cert in chain:
            intermediate_ca_certs.append(CertificateModel.save_certificate(cert))

        issuing_ca_model = IssuingCaModel()
        issuing_ca_model.unique_name = 'Issuing CA'
        issuing_ca_model.issuing_ca_certificate = issuing_ca_cert_model
        issuing_ca_model.root_ca_certificate = root_ca_cert_model
        issuing_ca_model.private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption())

        if intermediate_ca_certs:
            issuing_ca_cert_model.intermediate_ca_certificates = intermediate_ca_certs

        issuing_ca_model.save()

    @staticmethod
    def store_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_ca')

        for name, cert in certs.items():
            cert_path = tests_data_path / Path(f'{name}.pem')
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(encoding=Encoding.PEM))
            print(f'Stored EE certificate: {cert_path}')

    @staticmethod
    def save_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        for name, cert in certs.items():
            print(f'Saving EE certificate in DB: {name}')
            CertificateModel.save_certificate(cert)

    def handle(self, *args, **kwargs) -> None:

        root_1, root_1_key = self.create_root_ca('Root CA')
        issuing_1, issuing_1_key = self.create_issuing_ca(root_1_key, 'Root CA', 'Issuing CA')

        self.store_issuing_ca(issuing_1, [root_1], issuing_1_key)
        self.save_issuing_ca(issuing_1, root_1, [], issuing_1_key)

        ee_0, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 0')
        ee_1, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 1')
        ee_2, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 2')
        ee_3, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 3')
        ee_4, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 4')
        ee_5, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 5')
        ee_6, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 6')
        ee_7, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 7')
        ee_8, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 8')
        ee_9, _ = self.create_ee(issuing_1_key, 'Issuing CA', 'EE 9')

        ee_certs = {
            'ee0': ee_0,
            'ee1': ee_1,
            'ee2': ee_2,
            'ee3': ee_3,
            'ee4': ee_4,
            'ee5': ee_5,
            'ee6': ee_6,
            'ee7': ee_7,
            'ee8': ee_8,
            'ee9': ee_9,
        }

        self.store_ee_certs(ee_certs)
        self.save_ee_certs(ee_certs)