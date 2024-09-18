import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PKIFailure(Exception):
    """Base class for PKI Failures."""
    def __init__(self, message: str, code: int):
        """
        Initialize the PKIFailure.

        Args:
            message (str): The error message.
            code (int): The error code.
        """
        super().__init__(message)
        self.code = code
        logger.error(f"{self.__class__.__name__} initialized with message: '{message}' and code: {code}")


class BadAlg(PKIFailure):
    """Exception for bad algorithm (0)."""
    def __init__(self, message="Bad algorithm"):
        super().__init__(message, 0)

class BadMessageCheck(PKIFailure):
    """Exception for bad message check (1)."""
    def __init__(self, message="Bad message check"):
        super().__init__(message, 1)

class BadRequest(PKIFailure):
    """Exception for bad request (2)."""
    def __init__(self, message="Bad request"):
        super().__init__(message, 2)

class BadTime(PKIFailure):
    """Exception for bad time (3)."""
    def __init__(self, message="Bad time"):
        super().__init__(message, 3)

class BadCertId(PKIFailure):
    """Exception for bad certificate ID (4)."""
    def __init__(self, message="Bad certificate ID"):
        super().__init__(message, 4)

class BadDataFormat(PKIFailure):
    """Exception for bad data format (5)."""
    def __init__(self, message="Bad data format"):
        super().__init__(message, 5)

class WrongAuthority(PKIFailure):
    """Exception for wrong authority (6)."""
    def __init__(self, message="Wrong authority"):
        super().__init__(message, 6)

class IncorrectData(PKIFailure):
    """Exception for incorrect data (7)."""
    def __init__(self, message="Incorrect data"):
        super().__init__(message, 7)

class MissingTimeStamp(PKIFailure):
    """Exception for missing timestamp (8)."""
    def __init__(self, message="Missing timestamp"):
        super().__init__(message, 8)

class BadPOP(PKIFailure):
    """Exception for bad proof of possession (9)."""
    def __init__(self, message="Bad proof of possession"):
        super().__init__(message, 9)

class CertRevoked(PKIFailure):
    """Exception for certificate revoked (10)."""
    def __init__(self, message="Certificate revoked"):
        super().__init__(message, 10)

class CertConfirmed(PKIFailure):
    """Exception for certificate confirmed (11)."""
    def __init__(self, message="Certificate confirmed"):
        super().__init__(message, 11)

class WrongIntegrity(PKIFailure):
    """Exception for wrong integrity (12)."""
    def __init__(self, message="Wrong integrity"):
        super().__init__(message, 12)

class BadRecipientNonce(PKIFailure):
    """Exception for bad recipient nonce (13)."""
    def __init__(self, message="Bad recipient nonce"):
        super().__init__(message, 13)

class TimeNotAvailable(PKIFailure):
    """Exception for time not available (14)."""
    def __init__(self, message="Time not available"):
        super().__init__(message, 14)

class UnacceptedPolicy(PKIFailure):
    """Exception for unaccepted policy (15)."""
    def __init__(self, message="Unaccepted policy"):
        super().__init__(message, 15)

class UnacceptedExtension(PKIFailure):
    """Exception for unaccepted extension (16)."""
    def __init__(self, message="Unaccepted extension"):
        super().__init__(message, 16)

class AddInfoNotAvailable(PKIFailure):
    """Exception for additional info not available (17)."""
    def __init__(self, message="Additional info not available"):
        super().__init__(message, 17)

class BadSenderNonce(PKIFailure):
    """Exception for bad sender nonce (18)."""
    def __init__(self, message="Bad sender nonce"):
        super().__init__(message, 18)

class BadCertTemplate(PKIFailure):
    """Exception for bad certificate template (19)."""
    def __init__(self, message="Bad certificate template"):
        super().__init__(message, 19)

class SignerNotTrusted(PKIFailure):
    """Exception for signer not trusted (20)."""
    def __init__(self, message="Signer not trusted"):
        super().__init__(message, 20)

class TransactionIdInUse(PKIFailure):
    """Exception for transaction ID in use (21)."""
    def __init__(self, message="Transaction ID in use"):
        super().__init__(message, 21)

class UnsupportedVersion(PKIFailure):
    """Exception for unsupported version (22)."""
    def __init__(self, message="Unsupported version"):
        super().__init__(message, 22)

class NotAuthorized(PKIFailure):
    """Exception for not authorized (23)."""
    def __init__(self, message="Not authorized"):
        super().__init__(message, 23)

class SystemUnavail(PKIFailure):
    """Exception for system unavailable (24)."""
    def __init__(self, message="System unavailable"):
        super().__init__(message, 24)

class SystemFailure(PKIFailure):
    """Exception for system failure (25)."""
    def __init__(self, message="System failure"):
        super().__init__(message, 25)

class DuplicateCertReq(PKIFailure):
    """Exception for duplicate certificate request (26)."""
    def __init__(self, message="Duplicate certificate request"):
        super().__init__(message, 26)
