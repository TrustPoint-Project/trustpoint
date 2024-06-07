"""A."""


from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from django.core.management import BaseCommand, call_command
from pki.models import Certificate

from pki.oid import SignatureAlgorithmOid, PublicKeyAlgorithmOid, EllipticCurveOid
from cryptography.x509.oid import ExtensionOID

from cryptography.x509 import IssuerAlternativeName
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import datetime


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Just some stuff for manual testing.'

    def handle(self, *args, **kwargs) -> None:
        base_path = Path(__file__).parent.parent.parent.parent.parent.resolve()
        rsa_cert_path = base_path / Path('tests/data/rsa2048/rsa2048-root-ca-certificate.pem')
        rsa_key_path = base_path / Path('tests/data/rsa2048/rsa2048-root-ca-priv-key.pem')
        ecc_cert_path = base_path / Path('tests/data/secp256r1/secp256r1-root-ca-certificate.pem')
        ecc_key_path = base_path / Path('tests/data/secp256r1/secp256r1-root-ca-priv-key.pem')
        ext_cert = base_path / Path('tests/data/certs/cert.pem')
        ext_key = base_path / Path('tests/data/certs/key.pem')

        with open(rsa_cert_path, 'rb') as f:
            rsa_cert_pem = f.read()

        with open(rsa_key_path, 'rb') as f:
            rsa_key_pem = f.read()

        with open(ecc_cert_path, 'rb') as f:
            ecc_cert_pem = f.read()

        with open(ecc_key_path, 'rb') as f:
            ecc_key_pem = f.read()

        with open(ext_cert, 'rb') as f:
            ext_cert_pem = f.read()

        with open(ext_key, 'rb') as f:
            ext_key_pem = f.read()

        rsa_cert = x509.load_pem_x509_certificate(rsa_cert_pem)
        rsa_key =  serialization.load_pem_private_key(rsa_key_pem, password=None)

        ecc_cert = x509.load_pem_x509_certificate(ecc_cert_pem)
        ecc_key = serialization.load_pem_private_key(ecc_key_pem, password=None)

        ext_cert = x509.load_pem_x509_certificate(ext_cert_pem)
        ext_key = serialization.load_pem_private_key(ext_key_pem, password=None)

        Certificate.save_certificate(cert=rsa_cert, priv_key=rsa_key)
        Certificate.save_certificate(cert=ecc_cert, priv_key=ecc_key)
        Certificate.save_certificate(cert=ext_cert, priv_key=ext_key)

    print('\nDONE\n')
