
from pki.pki.cmp.errorhandling.pki_failures import (
    BadMessageCheck
)

class InitializationRespValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator for a ip body with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self.cert_resp_validator = CertRespValidator(self.cmp_body)

    def validate(self):
        self.cert_resp_validator.validate_ip()


class CertificationRespValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator for a cp body with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self.cert_resp_validator = CertRespValidator(self.cmp_body)

    def validate(self):
        self.cert_resp_validator.validate_cp()

class KeyUpdateRespValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator for a kup body with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self.cert_resp_validator = CertRespValidator(self.cmp_body)

    def validate(self):
        self.cert_resp_validator.validate_kup()

class CertRespValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator with ASN.1 encoded data.

        Args:
        - cmp_body (bytes): The ASN.1 encoded CMP body.
        """
        self.cmp_body = cmp_body
        self._response = None
        self._ip = None
        self._cp = None
        self._kup = None
        self._certResponse = None
        self._certifiedKeyPair = None

    @property
    def ip(self):
        return self._ip

    @property
    def cp(self):
        return self._cp

    @property
    def kup(self):
        return self._kup

    @property
    def certResponse(self):
        return self._certResponse

    @property
    def certifiedKeyPair(self):
        return self._certifiedKeyPair

    def validate_ip(self):
        """
        Validates the decoded CMP ip body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """
        self._validate_response_ip()
        self._validate_cert_response()
        self._validate_certified_key_pair()

    def validate_cp(self):
        """
        Validates the decoded CMP cp body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """
        self._validate_response_cp()
        self._validate_ca_pubs_absent()
        self._validate_cert_response()
        self._validate_certified_key_pair()

    def validate_kup(self):
        """
        Validates the decoded CMP kup body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """
        self._validate_response_kup()
        self._validate_ca_pubs_absent()
        self._validate_cert_response()
        self._validate_certified_key_pair()


    def _validate_response_ip(self):
        """
        Validates the 'ip' (Initialization Response) field of the CMP body.
        """
        self._ip = self.cmp_body['ip']
        self._response = self._ip
        if not self._ip.hasValue():
            raise BadMessageCheck("The 'ip' field is required.")

    def _validate_response_cp(self):
        """
        Validates the 'cp' (Certification Response) field of the CMP body.
        """
        self._cp = self.cmp_body['cp']
        self._response = self._cp
        if not self._cp.hasValue():
            raise BadMessageCheck("The 'cp' field is required.")

    def _validate_response_kup(self):
        """
        Validates the 'cp' (Certification Response) field of the CMP body.
        """
        self._kup = self.cmp_body['kup']
        self._response = self._kup
        if not self._kup.hasValue():
            raise BadMessageCheck("The 'kup' field is required.")

    def _validate_ca_pubs_absent(self):
        """
        Validates that 'caPubs' field is absent within the 'cp' filed.
        """
        ca_pubs = self._response['caPubs']
        if ca_pubs.hasValue():
            raise BadMessageCheck("The 'caPubs' field is not absent.")


    def _validate_cert_response(self):
        """
        Validates the 'response' field within the 'ip' field.
        """
        response = self._response['response']
        if not response.hasValue() or len(response) != 1:
            raise BadMessageCheck("The 'response' field is required and must contain exactly one 'CertResponse'.")

        self._certResponse = response[0]
        certReqId = self._certResponse['certReqId']
        status_info = self._certResponse['status']
        status = status_info['status']

        # Check certReqId
        if certReqId != 0:
            raise BadMessageCheck("The 'certReqId' field is required and must be 0.")

        # Check PKIStatusInfo.status
        allowed_status_values = [0, 1, 2, 3]  # This corresponds to 'accepted', 'grantedWithMods', 'rejection', 'waiting'
        if int(status) not in allowed_status_values:
            raise BadMessageCheck(f"The 'status' field must be one of {allowed_status_values}.")

        # Check failInfo
        if 'failInfo' in status_info and status_info['failInfo'].hasValue():
            if int(status) in [0, 1]:  # Accepted or GrantedWithMods
                raise BadMessageCheck("The 'failInfo' field must be absent if status is 'accepted' or 'grantedWithMods'.")

        if 'statusString' in status_info and status_info['statusString'].hasValue():
            pass

    def _validate_certified_key_pair(self):
        """
        Validates the 'certifiedKeyPair' field within the 'certResponse' field.
        """
        status = self._certResponse['status']['status']
        self._certifiedKeyPair = self._certResponse['certifiedKeyPair']

        if status in ['accepted', 'grantedWithMods']:
            if not self._certifiedKeyPair.hasValue():
                raise BadMessageCheck("The 'certifiedKeyPair' field is required if status is 'accepted' or 'grantedWithMods'.")

            if self._certifiedKeyPair.hasValue():
                certOrEncCert = self._certifiedKeyPair['certOrEncCert']['certificate']
                if not certOrEncCert.hasValue():
                    raise BadMessageCheck("The 'certificate' field within 'certOrEncCert' is required.")

                privateKey = self._certifiedKeyPair.get('privateKey')
                if privateKey.hasValue():
                    raise BadMessageCheck("The 'privateKey' field must be absent in case of local key generation or 'rejection'.")

        elif status == 'rejection':
            if self._certifiedKeyPair.hasValue():
                raise BadMessageCheck("The 'certifiedKeyPair' field must be absent if status is 'rejection'.")