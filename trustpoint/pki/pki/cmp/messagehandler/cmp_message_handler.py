from cryptography import x509
from pyasn1_modules import rfc4210, rfc2511
import logging
import traceback

from pki.models import CertificateModel

from pki.pki.cmp import (
    PKIBodyTypes, GenericHeaderValidator, ExtraCertsValidator, PoPVerifier, ErrorHandler, RFC4210Protection,
    CertMessageHandler, RevocationMessageHandler, GeneralMessageHandler, cert_templates,
    PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
    BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
    CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
    UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
    BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
    NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq
)

from pki.pki.request.message import HttpStatusCode

class CMPMessageHandler:
    def __init__(self, pki_message: rfc4210.PKIMessage, operation: str, alias: str = None):
        """
        Initialize the CMPMessageHandler with the necessary components.

        :param alias: str, the alias for the endpoint (optional).
        :param operation: str, the operation [one of ir,cr,kur,rr or genm] which should be performed.
        :param pki_message: rfc4210.PKIMessage, the decoded request data containing the PKI message.
        """
        self.pki_message = pki_message
        self.alias = alias
        self.operation = operation
        self.issuing_ca = None
        self.ca_cert = None
        self.ca_key = None
        self.protection_mode_signature = None
        self.protection_mode_pbm = None
        self.protection_mode_none = None
        self.shared_secret = None
        self.client_cert = None
        self.authorized_clients = None
        self.cert_chain = None
        self.cert_req_template = None

        self.protection = None
        self.header = self.pki_message.getComponentByName('header')
        self.body = None
        self.pki_body_type = None

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("CMPMessageHandler initialized with alias: %s", self.alias)


    def set_signature_based_protection(self, authorized_clients: list):
        """
        Define params for signature based protection.

        :param authorized_clients: list, a list of pem encoded certificates which are authorized.
        """
        self.protection_mode_signature = True
        self.authorized_clients = authorized_clients
        self.logger.info("Signature-based protection mode set with %d authorized clients", len(authorized_clients))

    def _is_valid_authorized_clients(self):
        self.logger.debug("Validating authorized clients list.")
        if self.authorized_clients:
            if not isinstance(self.authorized_clients, list):
                ValueError(f"authorized_clients must be a list")

            if len(self.authorized_clients) == 0:
                ValueError(f"authorized_clients must contain at least one certificate")

            for cert in self.authorized_clients:
                if not isinstance(cert, x509.Certificate):
                    ValueError(f"Each item in authorized_clients must be an instance of x509.Certificate")

    def _configure_alias(self):
        self.logger.debug("Configureing alias.")

        if self.alias:
            if self.alias in cert_templates:
                self.cert_req_template = cert_templates.get(self.alias)
            else:
                ValueError("No corresponding certificate template for provided alias")


    def set_pbm_based_protection(self, shared_secret: bytes):
        """
        Define params for a PBM protection.

        :param shared_secret: bytes, the shared secret (required for PBM mode).
        """
        self.protection_mode_pbm = True
        self.shared_secret = shared_secret
        self.logger.info("PBM-based protection mode set with shared secret.")

    def set_none_protection(self):
        """
        Define params for none protection.

        """
        self.protection_mode_none = True
        raise NotImplementedError("Protection mode None is not supported")


    def set_issuing_ca(self, issuing_ca_object):
        """
        Define params for a local testing setup.

        :param issuing_ca_object: an IssuingCa object.
        """
        self.issuing_ca_object = issuing_ca_object

        self.ca_cert = issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()
        self.ca_key = issuing_ca_object.private_key
        self.logger.info("Issuing CA set with certificate and key.")


    def process_request(self) -> tuple[bytes, HttpStatusCode]:
        """
        Processes the incoming CMP request and returns the response.

        :return: str, the response PKI message.
        """
        self.logger.info("Processing CMP request.")
        http_status_code = HttpStatusCode.OK

        try:
            self._is_valid_authorized_clients()
            self._configure_alias()
            #self._decode_request()
            self._determine_body_type()
            self._configure_protection()
            #self._validate_header()
            self._validate_extra_certs()
            self._verify_pop()

            response = self._handle_request()
            self.logger.info("Request processed successfully.")

        except (PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
                BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
                CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
                UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
                BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
                NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq) as e:
            self.logger.error(traceback.format_exc())
            response = self._handle_error(e, e.code)
            #http_status_code = HttpStatusCode.BAD_REQUEST
        except Exception as e:
            self.logger.error(traceback.format_exc())
            response = self._handle_error(e, 25)
            #http_status_code = HttpStatusCode.BAD_REQUEST

        return response, http_status_code

    def _update_authorized_clients(self):
        """
        Updates the list of authorized clients by validating the certificate associated with a Key Update Request (KUR)
        or Certificate Request (CR) message.

        For KUR and CR messages, the protection of the message must be signed using the private key corresponding to the
        original certificate being updated or renewed.
        """
        # TODO: Validate the certificate
        self.logger.debug(
            "CR or KUR message:protection must be signed using the respective private key of the oldcert.")
        extra_certs = self.pki_message.getComponentByName('extraCerts')[0]
        tbs_certificate = extra_certs.getComponentByName('tbsCertificate')

        self.logger.info(tbs_certificate)

        serial_number = tbs_certificate.getComponentByName('serialNumber')
        issuer = tbs_certificate.getComponentByName('issuer')

        issuer_ca = self.issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()
        issuer_public_bytes_hex = issuer_ca.subject.public_bytes().hex().upper()

        serial_number_hex = hex(serial_number)[2:].upper()

        certificate_query = CertificateModel.objects.filter(serial_number=serial_number_hex)

        if len(certificate_query) == 0:
            raise BadRequest("Certificate not found. You cannot update a certificate which was never issued")

        if len(certificate_query) > 1:
            raise BadRequest("Several certificates for serial number found")

        if not issuer_public_bytes_hex == certificate_query[0].issuer_public_bytes:
            raise BadRequest("Certificate serial number found but was not issued by associated Issuing CA")

        self.authorized_clients = [certificate_query[0].get_certificate_serializer().as_crypto()]

    def _configure_protection(self):
        """
        Configures the protection mechanism for the incoming PKI message.
        """
        # TODO: Protection of the kur MUST be performed using the certificate to be updated.
        self.logger.debug("Configuring protection.")

        self.protection = RFC4210Protection(self.pki_message, self.ca_cert)

        if self.protection_mode_pbm:
            self.logger.debug("Applying PBM protection mode.")
            self.protection.pbm_protection(shared_secret=self.shared_secret)

        if self.protection_mode_signature:
            self.logger.debug("Applying signature protection mode.")
            if self.pki_body_type.request_short_name in ["cr", "kur"]:
                self._update_authorized_clients()

            self.protection.signature_protection(ca_private_key=self.ca_key, authorized_clients=self.authorized_clients)

        self.protection.validate_protection()

    def _validate_header(self):
        """
        Validates the header of the PKI message.
        """
        self.logger.debug("Validating PKI message header.")
        validate_header = GenericHeaderValidator(self.header)
        validate_header.validate()
        self.logger.debug("Header validation completed.")


    def _determine_body_type(self):
        """
        Determines the body type of the PKI message.
        """
        self.logger.debug("Determining body type of PKI message.")
        self.body = self.pki_message.getComponentByName('body')
        self.pki_body_type = PKIBodyTypes()
        self.pki_body_type.get_response(self.body.getName())
        self.logger.info("Body type determined as %s.", self.body.getName())
        if not self.pki_body_type.request_short_name == self.operation:
            raise BadRequest(f"Expected {self.operation}, got {self.pki_body_type.request_short_name}")


    def _validate_extra_certs(self):
        """
        Validates the extra certificates in the PKI message.
        """
        self.logger.debug("Validating extra certificates in PKI message.")
        validate_extracerts = ExtraCertsValidator(self.pki_message, self.protection.protection_mode, self.pki_body_type.request_short_name)
        validate_extracerts.validate()
        self.logger.debug("Extra certificates validation completed.")


    def _verify_pop(self):
        """
        Verifies the Proof of Possession (PoP) in the PKI message.
        """
        self.logger.debug("Verifying Proof of Possession (PoP).")
        pop_verifier = PoPVerifier(self.pki_message, self.pki_body_type)
        pop_verifier.verify()
        self.logger.debug("Proof of Possession verification completed.")

    def _handle_request(self) -> bytes:
        """
        Handles the request and generates the appropriate response.

        :return: str, the response PKI message.
        """
        self.logger.debug("Handling request based on body type.")
        incoming = self.body.getComponentByName(self.pki_body_type.request_short_name)
        if not isinstance(incoming, type(self.pki_body_type.request_class)):
            raise BadRequest(f"Expected {self.pki_body_type.request_class}, got {type(incoming)}")

        if isinstance(incoming, rfc2511.CertReqMessages):
            self.logger.debug("Handling certificate request.")
            return self._handle_cert_request()
        elif isinstance(incoming, rfc4210.RevReqContent):
            self.logger.debug("Handling revocation request.")
            return self._handle_revocation_request()
        elif isinstance(incoming, rfc4210.GenMsgContent):
            self.logger.debug("Handling general request.")
            return self._handle_general_request()
        else:
            raise SystemFailure("PKI Body not supported")

    def _handle_cert_request(self) -> bytes:
        """
        Handles a certificate request.

        :return: str, the response PKI message.
        """
        cert_req_msg_handler = CertMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        cert_req_msg_handler.configure_request_template(self.cert_req_template)
        return cert_req_msg_handler.handle(self.issuing_ca_object)

    def _handle_revocation_request(self) -> bytes:
        """
        Handles a revocation request.

        :return: str, the response PKI message.
        """
        revocation_msg_handler = RevocationMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return revocation_msg_handler.handle(self.issuing_ca_object)

    def _handle_general_request(self) -> bytes:
        """
        Handles a general request.

        :return: str, the response PKI message.
        """
        general_msg_handler = GeneralMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return general_msg_handler.handle()

    def _handle_error(self, exception: Exception, error_code: int) -> bytes:
        """
        Handles any errors encountered during the processing of the request.

        :param exception: Exception, the exception that was raised.
        :param error_code: int, the error code to return in the response.
        :return: str, the error response PKI message.
        """
        self.logger.error("Handling error: %s with code %d", str(exception), error_code)
        error_handler = ErrorHandler()
        result = error_handler.handle_error(str(exception), error_code, self.header, self.protection, self.issuing_ca_object)
        self.logger.debug("Error handled, response generated.")

        return result
