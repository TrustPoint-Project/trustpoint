from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes, PrivateKeyTypes

from pki.util.keys import SignatureSuite

class CaGenerator:
    @staticmethod
    def generate_subject(common_name: str) -> x509.Name:

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
    def generate_ca_certificate(subject_ : x509.Name, issuer_ : x509.Name,
                                signing_key : PrivateKeyTypes, subject_key : CertificatePublicKeyTypes,
                                not_valid_before, not_valid_after) -> x509.Certificate:

        # Determine path length based on whether the CA is root or subordinate
        path_length = 1 if subject_ == issuer_ else 0

        certificate = x509.CertificateBuilder().subject_name(
            subject_
        ).issuer_name(
            issuer_
        ).public_key(
            subject_key
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
            x509.SubjectKeyIdentifier.from_public_key(subject_key), critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False
        ).sign(
            signing_key, SignatureSuite.get_hash_algorithm_by_key(signing_key), default_backend()
        )

        return certificate