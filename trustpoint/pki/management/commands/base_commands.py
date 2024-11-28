"""Something."""


from __future__ import annotations

import datetime
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from cryptography.x509.oid import NameOID
from pki.models import CertificateModel, IssuingCaModel

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class CertificateCreationCommandMixin:

    @staticmethod
    def create_root_ca(cn: str,
            validity_days: int = 7300) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(1, 0, 0)
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
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False
        )
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    @staticmethod
    def create_issuing_ca(
            issuer_private_key: rsa.RSAPrivateKey,
            issuer_cn: str, subject_cn,
            private_key: None | rsa.RSAPrivateKey = None,
            validity_days: int = 3650
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(1, 0, 0)
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
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), critical=False
        )
        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    @classmethod
    def store_issuing_ca(
            cls,
            issuing_ca_cert: x509.Certificate,
            chain: list[x509.Certificate],
            private_key: rsa.RSAPrivateKey,
            filename: str) -> None:

        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')
        issuing_ca_path = tests_data_path / Path(filename)
        # shutil.rmtree(tests_data_path, ignore_errors=True)
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
            private_key: rsa.RSAPrivateKey,
            unique_name: str ='issuing_ca') -> None:
        issuing_ca_cert_model = CertificateModel.save_certificate(issuing_ca_cert)
        root_ca_cert_model = CertificateModel.save_certificate(root_ca_cert, exist_ok=True)

        intermediate_ca_certs = []
        for cert in chain:
            intermediate_ca_certs.append(CertificateModel.save_certificate(cert))

        issuing_ca_model = IssuingCaModel()
        issuing_ca_model.unique_name = unique_name
        issuing_ca_model.issuing_ca_certificate = issuing_ca_cert_model
        issuing_ca_model.root_ca_certificate = root_ca_cert_model
        issuing_ca_model.private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()).decode()

        if intermediate_ca_certs:
            issuing_ca_cert_model.intermediate_ca_certificates = intermediate_ca_certs

        issuing_ca_model.save()

    @staticmethod
    def store_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')

        for name, cert in certs.items():
            cert_path = tests_data_path / Path(f'{name}.pem')
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(encoding=Encoding.PEM))
            print(f'Stored EE certificate: {cert_path}')

    @staticmethod
    def store_ee_keys(keys: dict[str, PrivateKey]) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')

        for name, key in keys.items():
            key_path = tests_data_path / Path(f'{name}.pem')
            with open(key_path, 'wb') as f:
                f.write(key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=NoEncryption()))
            print(f'Stored EE certificate: {key_path}')

    @staticmethod
    def save_ee_certs(certs: dict[str, x509.Certificate]) -> None:
        for name, cert in certs.items():
            print(f'Saving EE certificate in DB: {name}')
            CertificateModel.save_certificate(cert)

    @staticmethod
    def create_ee(
            issuer_private_key: rsa.RSAPrivateKey,
            issuer_cn: str, subject_cn,
            key_usage_extension: x509.KeyUsage=None,
            validity_days: int = 365) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        if validity_days >= 0:
            not_valid_before = datetime.datetime.today()
            not_valid_after = not_valid_before + (one_day * validity_days)
        else:
            not_valid_after = datetime.datetime.today() + (one_day * validity_days / 2)
            not_valid_before = not_valid_after + (one_day * validity_days)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        ]))
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        if key_usage_extension:
            builder = builder.add_extension(key_usage_extension, critical=False)

        certificate = builder.sign(
            private_key=issuer_private_key, algorithm=hashes.SHA256(),
        )
        return certificate, private_key

    @staticmethod
    def create_csr(number: int) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/issuing_cas')
        for i in range(number):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f'CSR Cert {i}'),
            ]))
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            csr = builder.sign(
                private_key, hashes.SHA256()
            )

            with open(tests_data_path / Path(f'csr{i}.pem'), 'wb') as f:
                f.write(csr.public_bytes(encoding=Encoding.PEM))
