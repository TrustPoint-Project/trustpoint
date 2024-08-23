from pyasn1.type import univ
from .. import BadMessageCheck
class GeneralMessageValidator:
    def __init__(self, body: univ.Sequence):
        """
        Initializes the validator with the body of the gene message.

        Args:
        - body (univ.Sequence): The body of the gene message as an ASN.1 sequence.
        """
        self.body = body
        self.info_type = None
        self.info_value = None

    def validate(self):
        """
        Validates the 'gene' message according to the specification.

        Returns:
        - bool: True if the 'gene' message is valid, False otherwise.
        - list: A list of validation error messages if the 'gene' message is invalid.
        """
        self._validate_genm()
        self._validate_info_type_and_value()

        return True

    def _validate_genm(self):
        """
        Validates that the genm field contains exactly one InfoTypeAndValue element.

        Raises:
        - BadMessageCheck: If the genm field does not contain exactly one InfoTypeAndValue element.
        """
        if 'genm' not in self.body:
            raise BadMessageCheck("genm field is missing from the gene message body.")

        genm_sequence = self.body['genm']

        if len(genm_sequence) != 1:
            raise BadMessageCheck("genm field MUST contain exactly one element of type InfoTypeAndValue.")

        info_type_and_value = genm_sequence[0]
        self.info_type = info_type_and_value['infoType']
        self.info_value = info_type_and_value['infoValue']


    def _validate_info_type_and_value(self):
        """
        Validates the infoType and infoValue fields.

        Raises:
        - BadMessageCheck: If infoType is missing or if infoValue does not match the requirements of the specific PKI management operation.
        """
        if not self.info_type:
            raise BadMessageCheck("infoType is missing from InfoTypeAndValue.")

        if self.info_type == univ.ObjectIdentifier('1.3.6.1.5.5.7.4.17'):
            if self.info_value.hasValue():
                raise BadMessageCheck("infoValue MUST be absent for OID 1.3.6.1.5.5.7.4.17.")

