from cryptography import x509

from pyasn1.type import univ
from pyasn1.codec.der import encoder
from . import BadMessageCheck

class GetCACertsValidator:
    def __init__(self, genp_response: univ.Sequence):
        """
        Initializes the validator with the genp response message.

        Args:
        - genp_response (univ.Sequence): The genp response message as an ASN.1 sequence.
        """
        self.genp_response = genp_response
        self.ca_certs = None
        self.errors = []

    def validate(self):
        """
        Validates the 'genp' response according to the 'Get CA Certificates' specification.

        Returns:
        - bool: True if the 'genp' response is valid, False otherwise.
        - list: A list of validation error messages if the 'genp' response is invalid.
        """
        self._get_infoValue()

        if self.ca_certs is None:
            # If no CA certificates are provided, ensure infoValue is absent
            if 'infoValue' in self.genp_response:
                raise BadMessageCheck("infoValue MUST be absent if no CA certificate is available.")
        else:
            # If CA certificates are provided, validate the certificate sequence
            self._validate_certificate_sequence(self.ca_certs)

    def _get_infoValue(self):
        """
        Extracts the 'infoValue' field from the genp response.

        Returns:
        - list: The 'infoValue' field as a list of certificates or None if infoValue is absent.
        """
        if 'infoValue' in self.genp_response:
            self.ca_certs = self.genp_response['infoValue']

    def _validate_certificate_sequence(self, ca_certs):
        """
        Validates that the infoValue contains a valid sequence of CA certificates.

        Args:
        - ca_certs (list): The 'infoValue' field as a list of certificates.
        """
        if not isinstance(ca_certs, univ.Sequence):
            raise BadMessageCheck("infoValue MUST be a sequence of certificates.")

        if len(ca_certs) == 0:
            raise BadMessageCheck("infoValue MUST contain at least one certificate if present.")

        for cert in ca_certs:
            self._validate_certificate(cert)

    def _validate_certificate(self, cert):
        """
        Validates an individual certificate in the sequence.

        Args:
        - cert (bytes): A certificate in DER format.
        """
        try:
            x509.load_der_x509_certificate(encoder.encode(cert))
        except Exception as e:
            raise BadMessageCheck(f"Invalid certificate found in infoValue sequence: {e}")
