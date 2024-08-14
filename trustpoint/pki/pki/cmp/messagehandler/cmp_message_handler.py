from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210, rfc2511
from pyasn1.type import univ
import logging
import traceback

from pki.pki.cmp.errorhandling.pki_failures import (
    PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
    BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
    CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
    UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
    BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
    NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq
)
from pki.pki.cmp.parsing.pki_body_types import PKIBodyTypes
from pki.pki.cmp.validator.header_validator import GenericHeaderValidator
from pki.pki.cmp.validator.extracerts_validator import ExtraCertsValidator
from pki.pki.cmp.validator.pop_verifier import PoPVerifier
from pki.pki.cmp.errorhandling.error_handler import ErrorHandler
from pki.pki.cmp.protection.protection import RFC4210Protection
from pki.pki.cmp.messagehandler.cert_message_handler import CertMessageHandler
from pki.pki.cmp.messagehandler.revocation_message_handler import RevocationMessageHandler
from pki.pki.cmp.messagehandler.general_message_handler import GeneralMessageHandler


class CMPMessageHandler:
    def __init__(self, request_data: rfc4210.PKIMessage, alias: str = None):
        """
        Initialize the CMPMessageHandler with the necessary components.

        :param alias: str, the alias for the endpoint (optional).
        :param request_data: rfc4210.PKIMessage, the decoded request data containing the PKI message.
        """
        self.alias = alias
        self.request_data = request_data
        self.issuing_ca = None
        self.ca_cert = None
        self.ca_key = None
        self.protection_mode_signature = None
        self.protection_mode_pbm = None
        self.protection_mode_none = None
        self.shared_secret = None
        self.client_cert = None
        self.authorized_clients = None

        self.pki_message = None
        self.protection = None
        self.header = None
        self.body = None
        self.pki_body_type = None

    def set_signature_based_protection(self, authorized_clients: list):
        """
        Define params for signature based protection.

        :param authorized_clients: list, a list of pem encoded certificates which are authorized.
        """
        self.protection_mode_signature = True
        self.authorized_clients = authorized_clients

    def _is_valid_authorized_clients(self):
        if self.authorized_clients:
            if not isinstance(self.authorized_clients, list):
                ValueError(f"authorized_clients must be a list")

            if len(self.authorized_clients) == 0:
                ValueError(f"authorized_clients must contain at least one certificate")

            for cert in self.authorized_clients:
                if not isinstance(cert, x509.Certificate):
                    ValueError(f"Each item in authorized_clients must be an instance of x509.Certificate")

    def set_pbm_based_protection(self, shared_secret: str):
        """
        Define params for a PBM protection.

        :param shared_secret: str, the shared secret (optional, required for PBM mode).
        """
        self.protection_mode_pbm = True
        self.shared_secret = shared_secret

    def set_none_protection(self):
        """
        Define params for none protection.

        """
        self.protection_mode_none = True
        raise NotImplementedError("Protection mode None is not supported")


    def set_issuing_ca(self, issuing_ca):
        """
        Define params for a local testing setup.

        :param ca_cert: bytes, the CA certificate.
        :param ca_key: bytes, the CA private key (optional, required for Signature mode).
        """
        self.issuing_ca = issuing_ca
        self.ca_cert = issuing_ca.get_issuing_ca_certificate()
        self.ca_key = issuing_ca.private_key()

    def process_request(self) -> str:
        """
        Processes the incoming CMP request and returns the response.

        :return: str, the response PKI message.
        """
        try:
            self._is_valid_authorized_clients()
            #self._decode_request()
            self._configure_protection()
            #self._validate_header()
            self._determine_body_type()
            self._validate_extra_certs()
            self._verify_pop()

            response = self._handle_request()
        except (PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
                BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
                CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
                UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
                BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
                NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq) as e:
            logging.error(traceback.format_exc())
            response = self._handle_error(e, e.code)
        except Exception as e:
            logging.error(traceback.format_exc())
            response = self._handle_error(e, 25)

        return response

    def _decode_request(self):
        """
        Decodes the incoming PKI message from the request data.
        """
        try:
            self.pki_message, _ = decoder.decode(self.request_data, asn1Spec=rfc4210.PKIMessage())
        except Exception as e:
            raise BadDataFormat("The formal ASN.1 syntax of the whole message is not compliant with the definitions given in CMP") from e

    def _configure_protection(self):
        """
        Configures the protection mechanism for the PKI message.
        """
        self.protection = self.configure_protection(self.pki_message)

    def configure_protection(self, pki_message: univ.Sequence) -> RFC4210Protection:
        """
        Configures the protection mechanism for the incoming PKI message.

        :param pki_message: univ.Sequence, the PKI message.
        :return: RFC4210Protection, the configured protection object.
        """
        protection = RFC4210Protection(pki_message, self.ca_cert)

        if self.protection_mode_pbm:
            protection.pbm_protection(shared_secret=self.shared_secret)

        if self.protection_mode_signature:
            protection.signature_protection(ca_private_key=self.ca_key, client_cert=self.client_cert)

        protection.validate_protection()
        return protection

    def _validate_header(self):
        """
        Validates the header of the PKI message.
        """
        self.header = self.pki_message.getComponentByName('header')
        validate_header = GenericHeaderValidator(self.header)
        validate_header.validate()

    def _determine_body_type(self):
        """
        Determines the body type of the PKI message.
        """
        self.body = self.pki_message.getComponentByName('body')
        self.pki_body_type = PKIBodyTypes()
        self.pki_body_type.get_response(self.body.getName())

    def _validate_extra_certs(self):
        """
        Validates the extra certificates in the PKI message.
        """
        validate_extracerts = ExtraCertsValidator(self.pki_message, self.protection.protection_mode, self.pki_body_type.request_short_name)
        validate_extracerts.validate()

    def _verify_pop(self):
        """
        Verifies the Proof of Possession (PoP) in the PKI message.
        """
        pop_verifier = PoPVerifier(self.pki_message, self.pki_body_type)
        pop_verifier.verify()

    def _handle_request(self) -> str:
        """
        Handles the request and generates the appropriate response.

        :return: str, the response PKI message.
        """
        incoming = self.body.getComponentByName(self.pki_body_type.request_short_name)
        if not isinstance(incoming, type(self.pki_body_type.request_class)):
            raise BadRequest(f"Expected {self.pki_body_type.request_class}, got {type(incoming)}")

        if isinstance(incoming, rfc2511.CertReqMessages):
            return self._handle_cert_request()
        elif isinstance(incoming, rfc4210.RevReqContent):
            return self._handle_revocation_request()
        elif isinstance(incoming, rfc4210.GenMsgContent):
            return self._handle_general_request()
        else:
            raise SystemFailure("PKI Body not supported")

    def _handle_cert_request(self) -> str:
        """
        Handles a certificate request.

        :return: str, the response PKI message.
        """
        cert_req_msg_handler = CertMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return cert_req_msg_handler.handle(self.ca_cert, self.ca_key)

    def _handle_revocation_request(self) -> str:
        """
        Handles a revocation request.

        :return: str, the response PKI message.
        """
        revocation_msg_handler = RevocationMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return revocation_msg_handler.handle()

    def _handle_general_request(self) -> str:
        """
        Handles a general request.

        :return: str, the response PKI message.
        """
        general_msg_handler = GeneralMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return general_msg_handler.handle()

    def _handle_error(self, exception: Exception, error_code: int) -> str:
        """
        Handles any errors encountered during the processing of the request.

        :param exception: Exception, the exception that was raised.
        :param error_code: int, the error code to return in the response.
        :return: str, the error response PKI message.
        """
        error_handler = ErrorHandler()
        return error_handler.handle_error(str(exception), error_code, self.header, self.protection)
