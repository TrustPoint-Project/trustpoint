from pyasn1.type import univ
from pki.pki.cmp.errorhandling.pki_failures import BadMessageCheck
from pyasn1_modules import rfc4210

class ErrorValidator:
    def __init__(self, body: univ.Sequence):
        """
        Initializes the validator with the body of the Ann error message.

        Args:
        - body (univ.Sequence): The body of the Ann error message as an ASN.1 sequence.
        """
        self.body = body
        self.pki_status_info = None

    def validate(self):
        """
        Validates the 'Ann error' message according to the specification.

        Returns:
        - bool: True if the 'Ann error' message is valid, False otherwise.
        - list: A list of validation error messages if the 'Ann error' message is invalid.
        """
        self._validate_error()
        self._validate_pki_status_info()

        return True

    def _validate_error(self):
        """
        Validates that the error field is present in the Ann error message.

        Raises:
        - BadMessageCheck: If the error field is missing.
        """
        if 'error' not in self.body:
            raise BadMessageCheck("The 'error' field is missing from the Ann error message body.")

        self.pki_status_info = self.body['error']['pKIStatusInfo']

    def _validate_pki_status_info(self):
        """
        Validates the pKIStatusInfo field according to the specification.

        Raises:
        - BadMessageCheck: If the pKIStatusInfo field is invalid.
        """
        if 'status' not in self.pki_status_info:
            raise BadMessageCheck("The 'status' field is missing from pKIStatusInfo.")

        status = self.pki_status_info['status']



        # The status MUST have the value "rejection"
        if status != rfc4210.PKIStatus("rejection"):
            raise BadMessageCheck("The 'status' field MUST have the value 'rejection'.")

        if 'statusString' in self.pki_status_info:
            status_string = self.pki_status_info['statusString']
            if not isinstance(status_string, rfc4210.PKIFreeText):
                raise BadMessageCheck("The 'statusString' field must be an OctetString.")

        if 'failInfo' in self.pki_status_info:
            fail_info = self.pki_status_info['failInfo']
            if not isinstance(fail_info, univ.BitString):
                raise BadMessageCheck("The 'failInfo' field must be a BitString.")
