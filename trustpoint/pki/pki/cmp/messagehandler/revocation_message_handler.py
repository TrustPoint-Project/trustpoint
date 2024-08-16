from pki.pki.cmp.builder.pki_body_creator import PkiBodyCreator
from pki.pki.cmp.builder.pki_message_creator import PKIMessageCreator
from pki.pki.cmp.builder.revocation_handler import RevocationHandler
from pki.pki.cmp.validator.revocation_req_validator import RevocationReqValidator
from pki.pki.cmp.builder.pki_header_creator import PKIHeaderCreator
import logging

class RevocationMessageHandler:
    def __init__(self, body, header, pki_body_type, protection):
        """
        Initialize the RevocationMessageHandler with the necessary components.

        :param body: univ.Sequence, the incoming body.
        :param header: univ.Sequence, the header of the incoming PKI message.
        :param pki_body_type: PKIBodyTypes, the PKI body type information.
        :param protection: RFC4210Protection, the protection information.
        """
        self.body = body
        self.incoming = self.body.getComponentByName(pki_body_type.request_short_name)
        self.header = header
        self.pki_body_type = pki_body_type
        self.protection = protection
        self.issuing_ca_object = None

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)  # Adjust logging level as needed
        self.logger.info("RevocationMessageHandler initialized")

        #self._validate()

    def _validate(self):
        validate_ir = RevocationReqValidator(self.body)
        validate_ir.validate()

    def handle(self, issuing_ca_object) -> bytes:
        """
        Handles the revocation request and generates an appropriate response PKI message.

        :param issuing_ca_object: The IssuingCa object.
        :return: bytes, the response PKI message.
        """
        self.issuing_ca_object = issuing_ca_object

        logging.info("Handling revocation request")
        revocation_handler = RevocationHandler(self.incoming, self.issuing_ca_object)
        logging.debug("RevocationHandler initialized with incoming request")

        revocation_response = revocation_handler.generate_response()
        logging.info("Revocation response generated")

        pki_body = self._create_pki_body(revocation_response)
        logging.debug("PKI body created for the response")

        pki_header = self._create_pki_header()
        logging.debug("PKI header created for the response")

        response_protection = self.protection.compute_protection(pki_header, pki_body)
        logging.info("Protection computed for the response PKI message")

        pki_message = self._create_pki_message(pki_body, pki_header, response_protection)
        logging.info("PKI message created successfully")

        return pki_message

    def _create_pki_body(self, revocation_response):
        """
        Helper method to create the PKI body for the response.

        :param revocation_response: The result from the revocation handler.
        :return: PKIBody, the created PKI body.
        """
        body_creator = PkiBodyCreator()
        body_creator.set_body_type(self.pki_body_type)
        return body_creator.create_pki_body(int_status=revocation_response)

    def _create_pki_header(self):
        """
        Helper method to create the PKI header for the response.

        :return: PKIHeader, the created PKI header.
        """
        header_creator = PKIHeaderCreator(self.header, self.issuing_ca_object)
        return header_creator.create_header()

    def _create_pki_message(self, pki_body, pki_header, response_protection):
        """
        Helper method to create the PKI message for the response.

        :param pki_body: The PKI body of the message.
        :param pki_header: The PKI header of the message.
        :param response_protection: The computed protection for the message.
        :return: str, the created PKI message.
        """
        pki_message_creator = PKIMessageCreator(pki_body, pki_header, self.pki_body_type, response_protection)
        return pki_message_creator.create_pki_message()

