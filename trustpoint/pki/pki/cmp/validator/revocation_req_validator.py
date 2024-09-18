from . import BadMessageCheck, ParseHelper

from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc5280
from pyasn1.type import univ


class RevocationReqValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self._rr = None
        self._certDetails = None
        self._serialNumber = None
        self._issuer = None
        self._crlEntryDetails = None

    @property
    def rr(self):
        return self._rr

    @property
    def certDetails(self):
        return self._certDetails

    @property
    def serialNumber(self):
        return self._serialNumber

    @property
    def issuer(self):
        return self._issuer

    @property
    def crlEntryDetails(self):
        return self._crlEntryDetails

    def validate(self):
        """
        Validates the decoded CMP body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """
        self._validate_rr()
        self._validate_cert_details()
        self._validate_crl_entry_details()

    def _validate_rr(self):
        """
        Validates the 'rr' (Revocation Request) field of the CMP body.
        """
        self._rr = self.cmp_body['rr']
        if not self._rr or len(self._rr) != 1:
            raise BadMessageCheck("The 'rr' field is required and must contain exactly one 'RevDetails'.")

    def _validate_cert_details(self):
        """
        Validates the 'certDetails' field within the 'rr' field.
        """
        self._certDetails = self._rr[0]['certDetails']

        self._serialNumber = self._certDetails['serialNumber']
        if not self._serialNumber.hasValue():
            raise BadMessageCheck(
                "The 'serialNumber' field is required and must contain the certificate's serialNumber attribute.")

        self._issuer = self._certDetails['issuer']
        if not self._issuer.hasValue():
            raise BadMessageCheck(
                "The 'issuer' field is required and must contain the issuer attribute of the certificate to be revoked.")

    def _validate_crl_entry_details(self):
        """
        Validates the 'crlEntryDetails' field within the 'rr' field.
        """
        self._crlEntryDetails = self._rr[0]['crlEntryDetails']
        if not self._crlEntryDetails or len(self._crlEntryDetails) != 1:
            raise BadMessageCheck("The 'crlEntryDetails' field is required and must contain exactly one 'reasonCode'.")

        reasonCode = self.extract_reason_code(self._crlEntryDetails)

        if reasonCode is None:
            raise BadMessageCheck("The 'reasonCode' field is required and must be a valid CRLReason value.")

    def extract_reason_code(self, crl_entry_details: univ.Sequence) -> str:
        """
        Extracts the reason code from the CRL entry details.

        :param crl_entry_details: Sequence, the ASN.1 sequence containing CRL entry details
        :return: str, the extracted reason code description
        """
        for extension in crl_entry_details:
            extn_id = extension.getComponentByName('extnID')
            if extn_id == rfc5280.id_ce_cRLReasons:
                extn_value = extension.getComponentByName('extnValue')
                reason_code, _ = decode(extn_value, asn1Spec=rfc5280.CRLReason())
                return ParseHelper.REASON_CODES.get(int(reason_code), 'unknown')
        return None