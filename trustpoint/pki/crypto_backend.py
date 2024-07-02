import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization


class CRLManager:
    """Manager to build and update crls"""
    def __init__(self, ca_cert, ca_private_key) -> None:
        self.ca_cert = ca_cert
        self.ca_private_key = ca_private_key

    def create_crl(self, revoked_certificates: list) -> bytes:
        """Builds crl based on provided revoked certificates

        Args: revoked_certificates (List): List of revoked certificates.

        Returns: crl in pem format.
        """
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(days=30))

        for cert in revoked_certificates:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(cert.cert_serial_number, 16)
            ).revocation_date(
                cert.revocation_datetime
            ).build()
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
        return crl.public_bytes(encoding=serialization.Encoding.PEM)
