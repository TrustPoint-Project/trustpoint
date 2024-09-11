"""Something."""


from __future__ import annotations

import datetime
import ipaddress
import shutil
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from . import Algorithm
from .base_commands import CertificateCreationCommandMixin
from django.core.management.base import BaseCommand


class Command(CertificateCreationCommandMixin, BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def _create_cert_chain(self, algorithm: Algorithm, path: Path) -> None:

        pem_root_cert, root_cert, root_private_key = self._create_certificate(
            common_name=f'{algorithm.value}-root-ca',
            algorithm=algorithm,
            path=path)

        pem_issuing_cert, issuing_cert, issuing_private = self._create_certificate(
            common_name=f'{algorithm.value}-issuing-ca',
            algorithm=algorithm,
            path=path,
            issuer=root_cert,
            issuer_priv_key=root_private_key
        )

        pem_ee_cert, ee_cert, ee_key = self._create_certificate(
            common_name=f'{algorithm.value}-ee',
            algorithm=algorithm,
            path=path,
            issuer=issuing_cert,
            issuer_priv_key=issuing_private
        )

        p12 = pkcs12.serialize_key_and_certificates(
            name=b'',
            key=ee_key,
            cert=ee_cert,
            cas=[root_cert, issuing_cert],
            encryption_algorithm=BestAvailableEncryption(b"password")
        )

        with open(path / f'{algorithm.value}.p12', 'wb') as f:
            f.write(p12)

        with open(path / f'{algorithm.value}-chain.pem', 'wb') as f:
            cert_chain = pem_root_cert + pem_issuing_cert + pem_ee_cert
            f.write(cert_chain.encode())

    @classmethod
    def _create_certificate(
            cls,
            common_name: str,
            algorithm: Algorithm,
            path: Path,
            issuer: None | x509.Certificate = None,
            issuer_priv_key: None | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = None,
            validity_days: int = 365) -> tuple[str, x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey]:

        if algorithm == Algorithm.RSA2048:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == Algorithm.RSA4096:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif algorithm == Algorithm.SECP256:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif algorithm == Algorithm.SECP521:
            private_key = ec.generate_private_key(ec.SECP521R1())
        else:
            raise ValueError('Unknown algorithm.')

        one_day = datetime.timedelta(1, 0, 0)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        if issuer is None:
            builder = builder.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]))
        else:
            builder = builder.issuer_name(issuer.subject)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        # ------------------------------------------------- Extensions -------------------------------------------------
        if issuer is None:
            ca = True
            path_length = 1
        elif issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1:
            ca = True
            path_length = 0
        else:
            ca = False
            path_length = None

        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=True,
                decipher_only=True
            ),
            critical=True
        )

        some_arbitrary_der_as_hex = (
            '30413130302E06035504030C275472757374506F696E7420526F6F74204341202D2'
            '0534543503235365231202D20534841323536310D300B060355040513044E6F6E65'
        )

        some_arbitrary_der = bytes.fromhex(some_arbitrary_der_as_hex)

        builder = builder.add_extension(
            x509.IssuerAlternativeName(
                [
                    x509.RFC822Name('trustpoint@trustpoint.de'),
                    x509.DNSName('trustpoint.de'),
                    x509.UniformResourceIdentifier('https://trustpoint.de'),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                    x509.IPAddress(ipaddress.IPv6Address('2001:0db8:85a3:0000:0000:8a2e:0370:7334')),
                    x509.IPAddress(ipaddress.IPv4Network('192.168.127.12/24', False)),
                    x509.IPAddress(ipaddress.IPv6Network('2001:db8:1234::/48')),
                    x509.RegisteredID(x509.ObjectIdentifier('2.5.4.3')),
                    x509.OtherName(type_id=x509.ObjectIdentifier('2.5.4.3'), value=some_arbitrary_der),

                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COMMON_NAME, 'Trustpoint Model Test'),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Trustpoint')
                        ])
                    )
                ]
            ),
            critical=False
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name('subject@trustpoint.de'),
                    x509.DNSName('subject.trustpoint.de'),
                    x509.UniformResourceIdentifier('https://subject.trustpoint.de'),
                    x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
                    x509.IPAddress(ipaddress.IPv6Address('2001:0db8:85a3:0000:0000:8a2e:0370:7334')),
                    x509.IPAddress(ipaddress.IPv4Network('192.168.127.12/24', False)),
                    x509.IPAddress(ipaddress.IPv6Network('2001:db8:1234::/48')),
                    x509.RegisteredID(x509.ObjectIdentifier('2.5.4.3')),
                    x509.OtherName(type_id=x509.ObjectIdentifier('2.5.4.3'), value=some_arbitrary_der),

                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COMMON_NAME, 'Subject Trustpoint Model Test'),
                            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Subject Trustpoint')
                        ])
                    )
                ]
            ),
            critical=False
        )

        if issuer_priv_key is None:
            certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
            )
        else:
            certificate = builder.sign(
                private_key=issuer_priv_key, algorithm=hashes.SHA256(),
            )

        pem_priv_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_cert = certificate.public_bytes(serialization.Encoding.PEM)

        with open(path / f'{common_name}-key.pem', 'wb') as f:
            f.write(pem_priv_key)

        with open(path / f'{common_name}-cert.pem', 'wb') as f:
            f.write(pem_cert)

        return pem_cert.decode(), certificate, private_key

    @staticmethod
    def _create_trust_store(path: Path):
        certs = ''
        for value in [algo.value for algo in Algorithm]:
            with open(path / f'{value}-chain.pem', 'r') as f:
                certs += f.read()

        with open(path / 'trust-store.pem', 'w') as f:
            f.write(certs)

    def handle(self, *args, **kwargs) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/certs')
        shutil.rmtree(tests_data_path, ignore_errors=True)
        tests_data_path.mkdir(exist_ok=True)

        self._create_cert_chain(algorithm=Algorithm.RSA2048, path=tests_data_path)
        self._create_cert_chain(algorithm=Algorithm.RSA4096, path=tests_data_path)
        self._create_cert_chain(algorithm=Algorithm.SECP256, path=tests_data_path)
        self._create_cert_chain(algorithm=Algorithm.SECP521, path=tests_data_path)

        self._create_trust_store(path=tests_data_path)

        for algo in Algorithm:
            cmd = (
                f'openssl verify -CAfile {tests_data_path}/{algo.value}-root-ca-cert.pem -untrusted '
                f'{tests_data_path}/{algo.value}-issuing-ca-cert.pem {tests_data_path}/{algo.value}-ee-cert.pem'
            )
            print(f'Created certificate chain with {algo.name} and SHA256.')
            print(f'Verifying certificate chain with {algo.name} and SHA256.')
            print(subprocess.check_output(cmd, shell=True).decode())