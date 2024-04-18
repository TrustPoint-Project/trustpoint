import io
import sys
from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509
import requests,base64
from util.x509.credentials import CredentialUploadHandler
from pki.models import IssuingCa
from django.core.files.uploadedfile import InMemoryUploadedFile

if TYPE_CHECKING:
    from util.x509.credentials import P12
    
    
class ESTProtocolHandler:
    @staticmethod
    def generate_csr(common_name,key_type):
        """Generates a 2048-bit RSA private key and CSR."""
        # Generate private key
        if (key_type == 'ECC_256'):
            key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend()
            )
        elif (key_type == 'ECC_384'):
            key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend()
            )
        elif (key_type == 'RSA_4096'):
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
        elif (key_type == 'RSA_2048'):
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            

        # Create subject information
        subject_ = x509.Name(
            [ 
#               x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name),
#               x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state_name),
#               x509.NameAttribute(x509.NameOID.LOCALITY_NAME, city_name),
#               x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
#               x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ORGANIZATIONAL_UNIT),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            ]
        )

        # Create CSR builder
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject_)
            .sign(key, hashes.SHA256(), default_backend())
        )

        # Return PEM encoded key and CSR
        return key, csr.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def est_simpleenroll(url, data=None, auth=None):
        """
        
        """

        headers = {"Content-Type": "application/pkcs10"}
        EST_URL=url+"/simpleenroll"
        
        response = requests.post(EST_URL, headers=headers, data=data, auth=auth, verify=False,timeout=10)
        
        response.raise_for_status()  # Raise exception for non-200 status codes

        return response
    
    @staticmethod
    def est_cacerts(url):
        """
        Download CA certificate chain
        """
        EST_URL=url+"/cacerts"
        response = requests.get(EST_URL, verify=False, timeout=10)

        response.raise_for_status()  # Raise exception for non-200 status codes

        return response
    
    @staticmethod
    def est_get_ca_certificate(est_user_name,est_password,est_url,unique_name,common_name,key_type):

        # Get CA chain
        try:
            response = ESTProtocolHandler.est_cacerts(est_url)
        except Exception as e:
            raise ValueError('EST Error (getcerts)',e)
        try:
            certs_der = base64.b64decode(response.text)
        except Exception as e:
            raise ValueError('EST Error (base64)',e)
        certs_chain = pkcs7.load_der_pkcs7_certificates(certs_der)
        
        # Generate private key and CSR
        private_key, csr_der = ESTProtocolHandler.generate_csr(common_name,key_type)
        csr_b64 = base64.b64encode(csr_der).decode("utf-8")
        
        auth = requests.auth.HTTPBasicAuth(est_user_name, est_password ) 
        cert_p12:P12
        # Enrollment request data
        data = csr_b64

        # Send enrollment request
        try:
            response = ESTProtocolHandler.est_simpleenroll(est_url, data, auth)
        except Exception as e:
            raise ValueError('EST Error (simplenroll)',e)

        # Parse the issued certificate
        try:
            cert_der = base64.b64decode(response.text)
        except Exception as e:
            raise ValueError('EST Error (base64)',e)

        certs = pkcs7.load_der_pkcs7_certificates(cert_der)
        cert_p12 = CredentialUploadHandler.parse_and_normalize_x509_crypto(certs[0],certs_chain,private_key)
        p12_bytes_io = io.BytesIO(cert_p12.public_bytes)
        p12_memory_uploaded_file = InMemoryUploadedFile(
                    p12_bytes_io, 'p12', f'{unique_name}.p12', 'application/x-pkcs12', sys.getsizeof(p12_bytes_io), None
                )
        ca = IssuingCa( unique_name=unique_name,
                    common_name=cert_p12.common_name,
#                    root_common_name=cert_p12.root_common_name,
                    not_valid_before=cert_p12.not_valid_before,
                    not_valid_after=cert_p12.not_valid_after,
                    key_type=cert_p12.key_type,
                    key_size=cert_p12.key_size,
                    curve=cert_p12.curve,
                    localization=cert_p12.localization,
                    config_type=IssuingCa.ConfigType.F_EST,
                    p12=p12_memory_uploaded_file,
                )

        ca.save()


    
