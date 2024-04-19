import io
import sys

from cryptography import x509
from django.core.exceptions import ValidationError
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from django.core.files.uploadedfile import InMemoryUploadedFile

from pki.models import Truststore
from util.x509.credentials import CredentialUploadHandler


class PEMCertificateValidator:
    """Class to validate PEM encoded certificates and extract details."""

    @staticmethod
    def validate_certificate(pem_data):
        """Check if the PEM data is a valid certificate and return details."""
        try:
            cert = CredentialUploadHandler.parse_pem_cert(pem_data.encode('utf-8'))

            common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if not common_names:
                raise ValidationError("Certificate must include a Common Name.")
            common_name = common_names[0].value

            public_key = cert.public_key()

            key_type, key_size, curve = PEMCertificateValidator.extract_key_details(public_key)

            pem_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
            pem_bytes_io = io.BytesIO(pem_cert)
            pem_memory_uploaded_file = InMemoryUploadedFile(
                pem_bytes_io, 'pem', f'{common_name}.pem', 'application/x-pem', sys.getsizeof(pem_bytes_io), None
            )

            truststore = Truststore(common_name=common_name,
                                    subject=cert.subject.rfc4514_string(),
                                    issuer=cert.issuer.rfc4514_string(),
                                    not_valid_before=cert.not_valid_before,
                                    not_valid_after=cert.not_valid_after,
                                    key_type=key_type,
                                    key_size=key_size,
                                    curve=curve,
                                    pem=pem_memory_uploaded_file,
                                    )

            truststore.save()
        except Exception as e:
            raise ValidationError(f'Invalid certificate: {str(e)}')

    @staticmethod
    def extract_key_details(public_key):
        """Extract details from the certificate's public key."""
        if isinstance(public_key, rsa.RSAPublicKey):
            return 'RSA', public_key.key_size, ""
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return 'ECC', public_key.key_size, public_key.curve.name
        else:
            ValidationError(f'Key type not supported')
