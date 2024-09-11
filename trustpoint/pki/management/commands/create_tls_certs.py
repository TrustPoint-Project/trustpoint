"""Something."""


from __future__ import annotations

import ipaddress
from typing import Union
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from django.core.management.base import BaseCommand
import subprocess

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]

BASE_PATH = Path(__file__).parent.parent.parent.parent.parent / 'tests/data/x509/'
SERVER_CERT_PATH =  BASE_PATH / 'https_server.crt'
SERVER_KEY_PATH = BASE_PATH / 'https_server.pem'


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Creates a TLS Server Certificate as required.'

    def handle(self, *args, **kwargs) -> None:
        one_day = datetime.timedelta(1, 0, 0)
        ipv4_addresses = subprocess.check_output('hostname -I', shell=True).decode().strip()
        ipv4_addresses = ipv4_addresses.split(' ')
        basic_constraints_extension = x509.BasicConstraints(ca=False, path_length=None)
        key_usage_extension = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            decipher_only=False,
            encipher_only=False
        )
        extended_key_usage_extension = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        subject_alt_name_content = [x509.DNSName('localhost'), x509.DNSName('trustpoint.local')]
        for ipv4 in ipv4_addresses:
            subject_alt_name_content.append(x509.IPAddress(ipaddress.IPv4Address(ipv4)))
        subject_alternative_names_extension = x509.SubjectAlternativeName(subject_alt_name_content)

        subject = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Trustpoint TLS Server Certificate'),
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, 'DE'),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, 'Trustpoint Project')
        ])
        issuer = subject

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 365))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(basic_constraints_extension, critical=True)
        builder = builder.add_extension(key_usage_extension, critical=False)
        builder = builder.add_extension(extended_key_usage_extension, critical=True)
        builder = builder.add_extension(subject_alternative_names_extension, critical=True)

        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        SERVER_CERT_PATH.write_text(certificate.public_bytes(serialization.Encoding.PEM).decode())
        SERVER_KEY_PATH.write_text(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        )
