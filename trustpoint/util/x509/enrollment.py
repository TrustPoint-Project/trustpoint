import io
import sys
from typing import TYPE_CHECKING

import cryptography.x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption, NoEncryption
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509
import requests, base64
from util.x509.credentials import CredentialUploadHandler
from pki.models import IssuingCaModel
from django.core.files.uploadedfile import InMemoryUploadedFile

if TYPE_CHECKING:
    from util.x509.credentials import P12


class Enrollment:

    @staticmethod
    def generate_key(key_type):
        """Generates a private key."""
        if (key_type == 'SECP256R1'):
            key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend()
                                          )
        elif (key_type == 'SECP384R1'):
            key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend()
                                          )
        elif (key_type == 'RSA4096'):
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
        elif (key_type == 'RSA2048'):
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
        else:
            raise ValueError("Unsupported algorithm type")

        return key

    def determine_key_type(key):
        """Determines the key type of the given key."""
        if isinstance(key, rsa.RSAPrivateKey):
            key_size = key.key_size
            if key_size == 2048:
                return 'RSA2048'
            elif key_size == 4096:
                return 'RSA4096'
            else:
                raise ValueError("Unsupported RSA key size")
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            curve_name = key.curve.name
            if curve_name == 'secp256r1':
                return 'SECP256R1'
            elif curve_name == 'secp384r1':
                return 'SECP384R1'
            else:
                raise ValueError("Unsupported ECC curve")
        else:
            raise TypeError("Unsupported key type")

    @staticmethod
    def generate_subject(common_name):

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

        return subject_

    @staticmethod
    def generate_csr(common_name, key_type):

        key = Enrollment.generate_key(key_type)
        subject_ = Enrollment.generate_subject(common_name)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject_)
            .sign(key, hashes.SHA256(), default_backend())
        )

        return key, csr.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def load_existing_p12(p12_path, password):
        """Load an existing P12 file."""
        if isinstance(password, str):
            password = password.encode()

        # Open and read the P12 file
        with open(p12_path, "rb") as file:
            p12_data = file.read()

        # Load the P12 contents
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data, password, default_backend()
        )
        return private_key, certificate, additional_certs

    @staticmethod
    def generate_certificate_chain(certificate, issuer_cert, additional_certs=None):
        """
        Generates a certificate chain starting from the given certificate to the issuer's certificate.
        Optionally includes additional certificates.
        """
        cert_chain = [certificate.public_bytes(serialization.Encoding.PEM)]
        if issuer_cert:
            cert_chain.append(issuer_cert.public_bytes(serialization.Encoding.PEM))
        if additional_certs:
            cert_chain.extend([cert.public_bytes(serialization.Encoding.PEM) for cert in additional_certs])
        return cert_chain

    @staticmethod
    def generate_root_ca(common_name, key_type, not_valid_before, not_valid_after, password):
        key = Enrollment.generate_key(key_type)
        subject_ = Enrollment.generate_subject(common_name)

        certificate = Enrollment.generate_ca_certificate(subject_=subject_,
                                                         issuer_=subject_,
                                                         subject_key=key,
                                                         signing_key=key,
                                                         not_valid_before=not_valid_before,
                                                         not_valid_after=not_valid_after)

        p12 = Enrollment.create_p12(key, certificate, password)

        return p12

    @staticmethod
    def generate_local_signed_sub_ca(unique_name, common_name, root_ca_unique_name, not_valid_before, not_valid_after,
                                     subject_password, issuer_password, config_type):

        root_ca_key, root_ca_cert, additional_certs = Enrollment.load_existing_p12(f"media/{root_ca_unique_name}.p12",
                                                                                   issuer_password)

        if root_ca_cert:
            root_ca_subject = root_ca_cert.subject
        else:
            root_ca_subject = None

        # Determine the key type from the root CA key
        key_type = Enrollment.determine_key_type(root_ca_key)

        subject_key = Enrollment.generate_key(key_type)
        subject_ = Enrollment.generate_subject(common_name)

        certificate = Enrollment.generate_ca_certificate(subject_=subject_,
                                                         issuer_=root_ca_subject,
                                                         subject_key=subject_key,
                                                         signing_key=root_ca_key,
                                                         not_valid_before=not_valid_before,
                                                         not_valid_after=not_valid_after)

        #p12 = Enrollment.create_p12(subject_key, certificate, subject_password, [root_ca_cert])

        cert_chain = [root_ca_cert] if root_ca_cert else []

        # If additional_certs is not None and includes other certificates
        if additional_certs:
            cert_chain.extend(additional_certs)

        cert_p12 = CredentialUploadHandler.parse_and_normalize_x509_crypto(certificate, cert_chain, subject_key)
        p12_bytes_io = io.BytesIO(cert_p12.public_bytes)
        p12_memory_uploaded_file = InMemoryUploadedFile(
            p12_bytes_io, 'p12', f'{unique_name}.p12', 'application/x-pkcs12', sys.getsizeof(p12_bytes_io), None
        )

        ca = IssuingCaModel(unique_name=unique_name,
                       common_name=cert_p12.common_name,
                       not_valid_before=cert_p12.not_valid_before,
                       not_valid_after=cert_p12.not_valid_after,
                       key_type=cert_p12.key_type,
                       key_size=cert_p12.key_size,
                       curve=cert_p12.curve,
                       localization=cert_p12.localization,
                       config_type=config_type,
                       p12=p12_memory_uploaded_file,
                       )

        ca.save()

    @staticmethod
    def generate_ca_certificate(subject_, issuer_, signing_key, subject_key, not_valid_before, not_valid_after):

        # Determine path length based on whether the CA is root or subordinate
        path_length = None if subject_ == issuer_ else 0

        certificate = x509.CertificateBuilder().subject_name(
            subject_
        ).issuer_name(
            issuer_
        ).public_key(
            subject_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        ).add_extension(
            x509.KeyUsage(digital_signature=False, key_encipherment=False,
                          key_cert_sign=True, key_agreement=False,
                          content_commitment=False, data_encipherment=False,
                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False
        ).sign(
            signing_key, hashes.SHA256(), default_backend()
        )

        return certificate

    @staticmethod
    def create_p12(key, cert, password, additional_certs=None):
        """Create a P12 file for the given key and certificate, optionally encrypted with a password."""
        # Determine the encryption method based on the presence of a password
        if password is not None:
            if isinstance(password, str):
                password = password.encode()  # Convert password to bytes if necessary
            encryption = BestAvailableEncryption(password)
        else:
            encryption = NoEncryption()

        # Serialize key and certificates into a PKCS#12 archive
        p12_data = pkcs12.serialize_key_and_certificates(
            b"",
            key,
            cert,
            additional_certs,
            encryption
        )

        return p12_data

    @staticmethod
    def load_existing_p12(p12_path, password):
        """Load an existing P12 file."""
        with open(p12_path, "rb") as file:
            p12 = pkcs12.load_key_and_certificates(
                file.read(), password, default_backend()
            )
        return p12
    
    @staticmethod
    def get_extension_for_oid_or_none(extensions: x509.Extensions, oid: NameOID) -> x509.Extension | None:
        """Determines if the given extensions contain an extension with the given OID.
        Args:
            extensions (x509.Extensions): The extensions to search.
            oid (NameOID): The OID to search for.
        """
        try:
            return extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return None
