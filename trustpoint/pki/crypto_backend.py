from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime


class CRLManager:
    """Manager to build and update crls"""
    def __init__(self, ca_cert, ca_private_key):
        self.ca_cert = ca_cert
        self.ca_private_key = ca_private_key

    def create_crl(self, revoked_certificates):
        # TODO @Dominik. After Alex rebuild the Database structure,
        # retrieve the serial number of certificate an merge both loops.
        """Builds crl based on provided revoked certificates

        Args: revoked_certificates (List): List of revoked certificates.

        Returns: crl in pem format.
        """

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(days=30))
        # revoked_certs = []

        # x = 0
        # for entry in revoked_certificates:
        #     x += 1
        #     revoked_certs.append({
        #         "serial_number": x,
        #         "revocation_date": entry.revocation_datetime
        #         })
        print('ERROR: CRLs are presently not correct! Fix hardcoded serial number in CRLManager.create_crl()!')

        for cert in revoked_certificates:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                123
                # TODO (Air): RevokedCertificateBuilder expects an integer, but actual certificate serial is a hex string?
                #cert.cert_serial_number
            ).revocation_date(
                cert.revocation_datetime
            ).build()
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
        return crl.public_bytes(encoding=serialization.Encoding.PEM)
