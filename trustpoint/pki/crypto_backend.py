import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ReasonFlags
from django.conf import settings

class CRLManager:
    """Manager to build and update CRLs"""
    def __init__(self, ca_cert, ca_private_key) -> None:
        self.ca_cert = ca_cert
        self.ca_private_key = ca_private_key

    def create_crl(self, revoked_certificates: list) -> bytes:
        """Builds crl based on provided revoked certificates

        Args:
            revoked_certificates (List): List of revoked certificates.

        Returns:
            CRL in PEM format.
        """
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(hours=settings.CRL_INTERVAL))

        for cert in revoked_certificates:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(cert.cert_serial_number, 16)
            ).revocation_date(
                cert.revocation_datetime
            ).add_extension(
                x509.CRLReason(ReasonFlags(cert.revocation_reason)), critical=False
            ).build()
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
        return crl.public_bytes(encoding=serialization.Encoding.PEM)

    def generate_crl(self, issuing_instance) -> bool:
        """Generate a CRL for the given issuing instance.

        Args:
            issuing_instance (IssuingCa or DomainProfile): The instance for which to generate the CRL.

        Returns:
            bool: True if CRL was generated and stored, False otherwise.
        """
        from .models import (  # Local import to avoid circular import
            CertificateRevocationList,
            DomainProfile,
            IssuingCa,
            RevokedCertificate,
        )

        if isinstance(issuing_instance, (IssuingCa, DomainProfile)):
            revoked_certificates = RevokedCertificate.objects.filter(
                issuing_ca=issuing_instance if isinstance(issuing_instance, IssuingCa) else issuing_instance.issuing_ca,
                domain_profile=None if isinstance(issuing_instance, IssuingCa) else issuing_instance
            )
            crl = self.create_crl(revoked_certificates).decode('utf-8')
            if crl:
                CertificateRevocationList.objects.update_or_create(
                    crl_content=crl,
                    ca=issuing_instance if isinstance(issuing_instance, IssuingCa) else issuing_instance.issuing_ca,
                    domain_profile=None if isinstance(issuing_instance, IssuingCa) else issuing_instance
                )
                return True
        return False

    @staticmethod
    def get_latest_crl(issuing_instance) -> 'CertificateRevocationList | None':
        """Retrieve the latest CRL from the database for the given issuing instance.

        Args:
            issuing_instance (IssuingCa or DomainProfile): The instance for which to retrieve the CRL.

        Returns:
            CertificateRevocationList or None: The latest CRL if exists, None otherwise.
        """
        from .models import CertificateRevocationList, DomainProfile, IssuingCa  # Local import to avoid circular import

        try:
            if isinstance(issuing_instance, IssuingCa):
                return CertificateRevocationList.objects.filter(ca=issuing_instance, domain_profile=None).latest('issued_at')
            elif isinstance(issuing_instance, DomainProfile):
                return CertificateRevocationList.objects.filter(domain_profile=issuing_instance).latest('issued_at')
        except CertificateRevocationList.DoesNotExist:
            return None
