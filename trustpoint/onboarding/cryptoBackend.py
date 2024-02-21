# Just a placeholder, this should be moved to a more appropriate location and contents adapted
### TODO TODO TODO sign_ldevid is Dragons with Lasers in central Berlin levels of a security risk TODO TODO TODO

import hashlib
import hmac
from cryptography import x509
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from devices.models import Device

from django.core.files.base import ContentFile


class CryptoBackend:
    def pbkdf2_hmac_sha256(hexpass, hexsalt, message=b'', iterations=1000000, dklen=32):
        pkey = hashlib.pbkdf2_hmac('sha256', bytes(hexpass, 'utf-8'), bytes(hexsalt, 'utf-8'), iterations, dklen)
        h = hmac.new(pkey, message, hashlib.sha256)
        return h.hexdigest()

    def get_trust_store():
        # TODO: server certificate location must be configurable
        with open('../tests/data/x509/https_server.crt', 'r') as certfile:
            return certfile.read()

    def sign_ldevid(csr_str: str, device: Device):
        csr = x509.load_pem_x509_csr(csr_str)
        # csr_str.read()

        # TODO: get .p12 from DB obviously, pending implementation of Endpoint profiles
        # TODO TODO TODO
        # TODO: save LDevID to device object
        with open('../tests/data/x509/rsa-long.p12', 'rb') as cafile:
            ca_p12 = serialization.pkcs12.load_key_and_certificates(
                cafile.read(), b'testing321'
            )  # obviously TODO (open question: how does trustpoint store the pkcs12 password?)
            private_ca_key = ca_p12[0]
            ca_cert = ca_p12[1]

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(
                datetime.now(timezone.utc) - timedelta(hours=1)  # backdate a bit in case of client clock skew
            )
            .not_valid_after(
                # TODO configurable validity period
                datetime.now(timezone.utc) + timedelta(days=365)
                # Sign our certificate with our private key
            )
            .sign(private_ca_key, hashes.SHA256())
        )

        device.serial_number = cert.serial_number
        device.certificate = ContentFile(cert.public_bytes(serialization.Encoding.PEM), name='ldevid.pem')
        device.save()  # need to keep track of the device once we send out a cert, even if onboarding fails afterwards, TODO but do it here?

        return cert.public_bytes(serialization.Encoding.PEM)

    def get_cert_chain():
        with open('../tests/data/x509/rsa-long.p12', 'rb') as cafile:
            ca_p12 = serialization.pkcs12.load_key_and_certificates(
                cafile.read(), b'testing321'
            )  # obviously TODO (open question: no way to get cert chain without password?)
            ca_cert = ca_p12[1]

        return ca_cert.public_bytes(serialization.Encoding.PEM)
