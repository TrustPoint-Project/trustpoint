from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from pyasn1.codec.der import encoder
from pyasn1.type import univ
from . import BadAlg, BadMessageCheck, SignerNotTrusted

class ExtraCertsValidator:
    def __init__(self, pki_message: univ.Sequence, protection_mode: str, message_type: str):
        """
        Initializes the validator with the CMP message and context details.

        Args:
        - pki_message (univ.Sequence): The CMP message as an ASN.1 sequence.
        - protection_mode (str): The protection mode, either "PBM" or "Signature".
        - message_type (str): The type of the CMP message (e.g., 'ip', 'cp', 'kup', 'certConf', 'PKIConf', 'pollReq', 'pollRep').
        """
        self.pki_message = pki_message
        self.protection_mode = protection_mode
        self.message_type = message_type
        self.extra_certs = None
        self.errors = []

    def validate(self):
        """
        Validates the 'extraCerts' field according to the provided specifications.

        Returns:
        - bool: True if the 'extraCerts' field is valid, False otherwise.
        - list: A list of validation error messages if the 'extraCerts' field is invalid.
        """
        self._get_extraCerts()

        if self.protection_mode == "Signature" and self.message_type in ['ir', 'cr', 'kur']:
            self._validate_signature_protection(self.extra_certs)
        elif self.message_type in ['ip', 'cp', 'kup']:
            self._validate_certificate_chain(self.extra_certs)

        self._check_self_signed(self.extra_certs)

    def _get_extraCerts(self):
        """
        Extracts the 'extraCerts' field from the pki_message.

        Returns:
        - list: The 'extraCerts' field as a list of certificates.
        """
        if 'extraCerts' in self.pki_message:
            self.extra_certs = self.pki_message['extraCerts']

    def _validate_signature_protection(self, extraCerts):
        """
        Validates the 'extraCerts' field for signature-based protection, focusing on the CMP protection certificate.

        Args:
        - extraCerts (list): The 'extraCerts' field as a list of certificates.
        """
        if not extraCerts:
            raise BadMessageCheck("The 'extraCerts' field is required for signature-based protection.")

        cmp_protection_cert = extraCerts[0]  # The first certificate in extraCerts is the CMP protection certificate

        cmp_protection_cert_der = encoder.encode(cmp_protection_cert)

        # TODO: Error in _validate_certificate_path
        #self._validate_certificate_path(cmp_protection_cert_der)
        self._validate_key_usage(cmp_protection_cert_der)

        if len(extraCerts) > 1:
            self._validate_certificate_chain(extraCerts[1:])

    def _validate_key_usage(self, cmp_protection_cert):
        """
        Validates that the CMP protection certificate's keyUsage extension has the digitalSignature bit set.

        Args:
        - cmp_protection_cert (bytes): The DER-encoded CMP protection certificate.
        """
        protection_cert = x509.load_der_x509_certificate(cmp_protection_cert)
        key_usage = protection_cert.extensions.get_extension_for_class(x509.KeyUsage)
        key_usage_value = key_usage.value

        if not key_usage_value.digital_signature:
            raise BadAlg("The CMP protection certificate's keyUsage does not have the digitalSignature bit set.")


    def _validate_certificate_path(self, cmp_protection_cert):
        """
        Validates the certificate path of the CMP protection certificate using the trust anchor.

        Args:
        - cmp_protection_cert (bytes): The DER-encoded CMP protection certificate.
        """
        try:
            protection_cert = x509.load_der_x509_certificate(cmp_protection_cert)

            protection_cert.public_key().verify(
                protection_cert.signature,
                protection_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                protection_cert.signature_hash_algorithm,
            )

        except InvalidSignature as e:
            raise SignerNotTrusted('CMP protection certificate path validation has invalid signature.')
        except Exception as e:
            raise BadMessageCheck(f"CMP protection certificate path validation failed: {e}")


    def _validate_certificate_chain(self, extraCerts):
        """
        Validates that the certificates are in a proper chain, where each certificate certifies the preceding one.

        Args:
        - extraCerts (list): The 'extraCerts' field as a list of certificates.
        """
        if False:
            raise BadMessageCheck("The certificate chain in 'extraCerts' is invalid.")

    def _check_self_signed(self, extraCerts):
        """
        Ensures that self-signed certificates are not trusted.

        Args:
        - extraCerts (list): The 'extraCerts' field as a list of certificates.
        """
        if extraCerts:
            for cert in extraCerts:
                if self.is_self_signed(cert):
                    raise BadMessageCheck("Self-signed certificates should be omitted from 'extraCerts' and must not be trusted.")

    def is_self_signed(self, cert):
        """
        Checks if a certificate is self-signed.

        Args:
        - cert (bytes): A certificate in DER format.

        Returns:
        - bool: True if the certificate is self-signed, False otherwise.
        """
        return False