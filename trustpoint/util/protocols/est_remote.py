"""Implements EST client protocol for CA certificate retrieval

TODO: Update this code and integrate it into the PKI app"""

from __future__ import annotations

import base64
import io
import sys
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from django.core.files.uploadedfile import InMemoryUploadedFile
from pki.models import IssuingCa
from pki.util.keys import SignatureSuite
from requests import Response, auth, get, post

from util.x509.credentials import CredentialUploadHandler

if TYPE_CHECKING:
    from util.x509.credentials import P12


class ESTProtocolHandler:
    """EST client protocol handler"""
    @staticmethod
    def generate_csr(common_name:str,key_type:str) -> tuple[ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey, bytes]:
        """Creates a RSA or EC private key and a CSR

        Args:
            common_name (str): CommonName in CSR
            key_type (str): Type of key pair (RSA or EC)
        """
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
        #TODO:(mkr@achelos) define DN components that should be modifiable
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
            .sign(key, SignatureSuite.get_hash_algorithm_by_key(key), default_backend())
        )

        # Return PEM encoded key and CSR
        return key, csr.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def est_simpleenroll(url:str, data:str, auth:str) -> Response:
        #TODO:(mkr@achelos) implement simplereenroll if applicable
        """_summary_

        Args:
            url (str): The URL of the EST-Server (https://x.x.x.x/.well-known(est/<ALIAS>))
            data (str): pkcs#10 csr request
            auth (str): _description_. Defaults to None.

        Returns:
            requests.Response: _description_
        """
        headers = {'Content-Type': 'application/pkcs10'}
        est_url=url+'/simpleenroll'
        response = post(est_url, headers=headers, data=data, auth=auth, verify=False,timeout=10)
        response.raise_for_status()  # Raise exception for non-200 status codes

        return response

    @staticmethod
    def est_cacerts(url:str) -> Response:
        #TODO(mkr@achelos): find a way to use TLS-Server certificate to verify connection
        """Retrieves the certificate chain from the EST server using the "cacerts" command

        Args:
            url (str): URL of EST server (https://x.x.x.x/.well-known(est/<ALIAS>)

        Returns:
            Response: response of the EST server
        """
        est_url=url+'/cacerts'
        response = get(est_url, verify=False, timeout=10)

        response.raise_for_status()  # Raise exception for non-200 status codes

        return response

    @staticmethod
    def est_get_ca_certificate(est_user_name:str,est_password:str,est_url:str,unique_name:str,
                               common_name:str,key_type:str) -> None:
        """Retrieves a CA certificate from an EST server

        Args:
            est_user_name (str): name for EST authentication
            est_password (str): password for EST authentication
            est_url (str): URL of EST server (https://x.x.x.x/.well-known(est/<ALIAS>)
            unique_name (str): unique name for the certificate for db storage
            common_name (str): common name in CSR DN
            key_type (str): type of key (RSA or EC)

        Raises:
            ValueError: Various error cases
        """
        # Get CA chain
        try:
            response = ESTProtocolHandler.est_cacerts(est_url)
        except Exception as e:
            error_message='EST Error (cacerts)'
            raise ValueError(error_message,e) from e
        try:
            certs_der = base64.b64decode(response.text)
        except Exception as e:
            error_message='EST Error (b64decode)'
            raise ValueError(error_message,e) from e
        certs_chain = pkcs7.load_der_pkcs7_certificates(certs_der)

        # Generate private key and CSR
        private_key, csr_der = ESTProtocolHandler.generate_csr(common_name,key_type)
        csr_b64 = base64.b64encode(csr_der).decode('utf-8')

        http_auth = auth.HTTPBasicAuth(est_user_name, est_password )
        cert_p12:P12
        # Enrollment request data
        data = csr_b64

        # Send enrollment request
        try:
            response = ESTProtocolHandler.est_simpleenroll(est_url, data, http_auth)
        except Exception as e:
            error_message='EST Error (simplenroll)'
            raise ValueError(error_message,e) from e

        # Parse the issued certificate
        try:
            cert_der = base64.b64decode(response.text)
        except Exception as e:
            error_message='EST Error (b64decode)'
            raise ValueError(error_message,e) from e

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

