"""Something."""


from __future__ import annotations


from django.core.management import BaseCommand
from pathlib import Path
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import ipaddress


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Removes all migrations, deletes db and runs makemigrations and migrate afterwards.'

    def handle(self, *args, **kwargs) -> None:
        tests_data_path = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/certs')
        shutil.rmtree(tests_data_path, ignore_errors=True)
        tests_data_path.mkdir(exist_ok=True)

        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'cryptography.io'),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        # ------------------------------------------------- Extensions -------------------------------------------------

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=True
            ),
            critical=False
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

        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
        )

        pem_priv_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(tests_data_path / 'key.pem', 'wb') as f:
            f.write(pem_priv_key)

        with open(tests_data_path / 'cert.pem', 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
