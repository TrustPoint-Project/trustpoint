from . import BadMessageCheck


class RevocationRespValidator:
    def __init__(self, cmp_body):
        """
        Initializes the validator with ASN.1 encoded data.

        Args:
        - cmp_body (dict): The ASN.1 encoded CMP body as a dictionary.
        """
        self.cmp_body = cmp_body
        self._rp = None
        self._status = None
        self._statusString = None
        self._failInfo = None

    @property
    def rp(self):
        return self._rp

    @property
    def status(self):
        return self._status

    @property
    def statusString(self):
        return self._statusString

    @property
    def failInfo(self):
        return self._failInfo

    def validate(self):
        """
        Validates the decoded CMP body according to the specified requirements.

        Returns:
        - bool: True if the CMP body is valid, False otherwise.
        - list: A list of validation error messages if the body is invalid.
        """

        self._validate_rp()
        self._validate_status()
        self._validate_fail_info()


    def _validate_rp(self):
        """
        Validates the 'rp' (Response) field of the CMP body.
        """
        self._rp = self.cmp_body['rp']
        if not self._rp :
            raise BadMessageCheck("The 'rp' field is required and must contain exactly one 'PKIStatusInfo'.")

    def _validate_status(self):
        """
        Validates the 'status' field within the 'rp' field.
        """
        status_info = self._rp['status'][0]
        self._status = self._rp['status'][0]['status']

        if self._status is None:
            raise BadMessageCheck("The 'status' field is missing in the 'PKIStatusInfo'.")

        status_str = str(self._status)

        valid_statuses = ["accepted", "rejection"]

        if str(self._status) not in valid_statuses:
            raise BadMessageCheck(f"The 'status' field must be one of {valid_statuses}. Current value: {status_str}")

        self._statusString = self._rp['status'][0]['statusString']

        if self._statusString.hasValue():
            if self._statusString and not isinstance(self._statusString, str):
                # TODO: Does not work right now
                raise BadMessageCheck("The 'statusString' field must be a human-readable string.")

    def _validate_fail_info(self):
        """
        Validates the 'failInfo' field within the 'rp' field.
        """
        self._failInfo = self._rp['status'][0]['failInfo']

        if self._status == "accepted" and self._failInfo is not None:
            raise BadMessageCheck("The 'failInfo' field must be absent if the status is 'accepted'.")

        if self._status == "rejection" and self._failInfo is None:
            raise BadMessageCheck(
                "The 'failInfo' field may be present if the status is 'rejection', but it is currently absent.")
