from pyasn1.type.useful import GeneralizedTime
import datetime
from pki.pki.cmp.errorhandling.pki_failures import (
    BadMessageCheck, BadDataFormat, BadRecipientNonce, BadSenderNonce,
    UnsupportedVersion
)

class GenericHeaderValidator:
    def __init__(self, header):
        """
        Initializes the validator with ASN.1 encoded data.

        Args:
        - header (dict): The CMP header fields as a dictionary.
        """
        self.header = header

    def validate(self):
        """
        Validates the CMP header according to the specified requirements.

        Returns:
        - bool: True if the header is valid, False otherwise.
        - list: A list of validation error messages if the header is invalid.
        """
        self._validate_pvno()
        self._validate_sender()
        self._validate_recipient()
        self._validate_message_time()
        self._validate_protection_alg()
        self._validate_sender_kid()
        self._validate_transaction_id()
        self._validate_sender_nonce()
        self._validate_recip_nonce()
        self._validate_implicit_confirm()
        self._validate_confirm_wait_time()
        self._validate_cert_profile()

    def _validate_pvno(self):
        """
        Validates the 'pvno' (Protocol Version Number) field.
        """
        pvno = self.header['pvno']
        if pvno is None:
            raise BadMessageCheck("The 'pvno' field is required.")
        elif pvno not in [2, 3]:
            raise UnsupportedVersion("The 'pvno' field must be 2 or 3 according to CMP v2 or v3.")

    def _validate_sender(self):
        """
        Validates the 'sender' field.
        """
        sender = self.header['sender']
        if sender is None:
            raise BadMessageCheck("The 'sender' field is required.")

    def _validate_recipient(self):
        """
        Validates the 'recipient' field.
        """
        recipient = self.header['recipient']
        if recipient is None:
            raise BadMessageCheck("The 'recipient' field is required.")

    def _validate_message_time(self, time_threshold_seconds=300):
        """
        Validates the 'messageTime' field if present.

        Args:
        - time_threshold_seconds (int): The acceptable threshold in seconds within which the messageTime should fall.
                                        Default is 300 seconds (5 minutes).
        """
        if 'confirmWaitTime' in self.header:
            if 'messageTime' not in self.header:
                raise BadMessageCheck("The 'messageTime' field is required when 'confirmWaitTime' is present.")

        if 'messageTime' in self.header:
            message_time = self.header['messageTime']
            if not isinstance(message_time, GeneralizedTime):
                raise BadMessageCheck("The 'messageTime' field must be in GeneralizedTime format.")
            else:
                message_time_dt = datetime.datetime.strptime(str(message_time), '%Y%m%d%H%M%SZ')
                if message_time_dt.tzinfo is None:
                    message_time_dt = message_time_dt.replace(tzinfo=datetime.UTC)

                current_time = datetime.datetime.now(datetime.UTC)
                time_diff = abs((current_time - message_time_dt).total_seconds())

                if time_diff > time_threshold_seconds:
                    raise BadMessageCheck(
                        "The 'messageTime' field is not within the acceptable range of the current time.")

    def _validate_protection_alg(self):
        """
        Validates the 'protectionAlg' field.
        """
        protection_alg = self.header['protectionAlg']
        if protection_alg is None:
            raise BadMessageCheck("The 'protectionAlg' field is required.")

    def _validate_sender_kid(self):
        """
        Validates the 'senderKID' field if present.
        """
        sender_kid = self.header['senderKID']
        protection_alg = self.header['protectionAlg']

        if sender_kid is None:
            return

        if 'MAC' in protection_alg:
            if sender_kid != self.header.get('sender', {}).get('commonName'):
                raise BadMessageCheck("The 'senderKID' must match the 'commonName' in the 'sender' field for MAC-based protection.")
        elif 'SIG' in protection_alg and sender_kid != self.header.get('sender', {}).get('SubjectKeyIdentifier'):
            raise BadMessageCheck("The 'senderKID' must match the 'SubjectKeyIdentifier' in the CMP protection certificate for signature-based protection.")

    def _validate_transaction_id(self):
        """
        Validates the 'transactionID' field.
        """
        transaction_id = self.header['transactionID']
        if transaction_id is None:
            raise BadDataFormat("The 'transactionID' field is required.")

    def _validate_sender_nonce(self):
        """
        Validates the 'senderNonce' field.
        """
        sender_nonce = self.header['senderNonce']
        if sender_nonce is None:
            raise BadSenderNonce("The 'senderNonce' field is required.")

    def _validate_recip_nonce(self):
        """
        Validates the 'recipNonce' field if present.
        """
        recip_nonce = self.header['recipNonce']
        if recip_nonce is not None and not self.header['senderNonce']:
            raise BadRecipientNonce("The 'recipNonce' field must match the 'senderNonce' of the previous message.")

    def _validate_implicit_confirm(self):
        """
        Validates the 'implicitConfirm' field if present.
        """
        if 'implicitConfirm' in self.header:
            implicit_confirm = self.header['implicitConfirm']
            confirm_wait_time = 'confirmWaitTime' in self.header

            if 'ImplicitConfirmValue' not in implicit_confirm or implicit_confirm['ImplicitConfirmValue'] is not None:
                raise BadMessageCheck("The 'ImplicitConfirmValue' in 'implicitConfirm' must be NULL.")
            if confirm_wait_time:
                raise BadMessageCheck("The 'confirmWaitTime' field is prohibited if 'implicitConfirm' is included.")

    def _validate_confirm_wait_time(self):
        """
        Validates the 'confirmWaitTime' field if present.
        """
        if 'confirmWaitTime' in self.header:
            confirm_wait_time = self.header['confirmWaitTime']
            if not isinstance(confirm_wait_time, GeneralizedTime):
                raise BadMessageCheck("The 'confirmWaitTime' must be a GeneralizedTime value.")

    def _validate_cert_profile(self):
        """
        Validates the 'certProfile' field if present.
        """
        if 'certProfile' in self.header:
            cert_profile = self.header['certProfile']
            if not cert_profile.hasValue():
                raise BadMessageCheck("The 'certProfile' field is required to contain a value.")
            else:
                cert_profile_value = cert_profile['CertProfileValue']
                if not cert_profile_value or not isinstance(cert_profile_value, str):
                    raise BadMessageCheck("The 'certProfile' must contain a sequence of one UTF8String element.")