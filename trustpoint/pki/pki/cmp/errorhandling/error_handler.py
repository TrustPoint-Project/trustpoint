from pyasn1.type import univ
from ..builder.pki_message_creator import PKIMessageCreator
from ..builder.pki_body_creator import PkiBodyCreator
from ..parsing.pki_body_types import PKIBodyTypes
from ..protection.protection import RFC4210Protection
from .pki_failures import SystemFailure
from ..builder.pki_header_creator import PKIHeaderCreator

class ErrorHandler:
    """
    A class to handle errors and generate appropriate PKI error responses.
    """

    def handle_error(self, error_str: str, error_code: int, header: univ.Sequence,
                     protection: RFC4210Protection) -> str:
        """
        Handles errors by generating an appropriate error response.

        :param error_str: str, the error message.
        :param error_code: int, the error code.
        :param header: univ.Sequence, the header of the incoming PKI message.
        :param protection: RFC4210Protection, the protection information.
        :return: str, the error response PKI message.
        """
        try:
            pki_body_type = self._get_error_body_type()
            pki_body = self._create_pki_body(error_str, error_code, pki_body_type)
            pki_header = self._create_pki_header(header, protection)

            response_protection = protection.compute_protection(pki_header, pki_body)

            pki_message = self._create_pki_message(pki_body, pki_header, pki_body_type, response_protection)

            return pki_message
        except Exception as e:
            raise SystemFailure("Exception while creating the error response") from e

    def _get_error_body_type(self):
        """
        Retrieves the PKI body type for an error response.

        :return: PKIBodyTypes, the PKI body type set to error response.
        """
        pki_body_type = PKIBodyTypes()
        pki_body_type._set_error_response()
        return pki_body_type

    def _create_pki_body(self, error_str, error_code, pki_body_type):
        """
        Creates the PKI body for the error response.

        :param error_str: str, the error message.
        :param error_code: int, the error code.
        :param pki_body_type: PKIBodyTypes, the PKI body type information.
        :return: PKIBody, the created PKI body.
        """
        cert_req_id = univ.Integer(0)

        body_creator = PkiBodyCreator()
        body_creator.set_cert_req_id(cert_req_id)
        body_creator.set_body_type(pki_body_type)
        body_creator.set_fail(int_fail=error_code, str_fail=error_str)
        return body_creator.create_pki_body(int_status=2)

    def _create_pki_header(self, header, protection):
        """
        Creates the PKI header for the error response.

        :param header: univ.Sequence, the header of the incoming PKI message.
        :param protection: RFC4210Protection, the protection information.
        :return: PKIHeader, the created PKI header.
        """
        header_creator = PKIHeaderCreator(header, protection.ca_cert)
        return header_creator.create_header()

    def _create_pki_message(self, pki_body, pki_header, pki_body_type, response_protection):
        """
        Creates the PKI message for the error response.

        :param pki_body: The PKI body of the message.
        :param pki_header: The PKI header of the message.
        :param pki_body_type: PKIBodyTypes, the PKI body type information.
        :param response_protection: The computed protection for the message.
        :return: str, the created PKI message.
        """
        pki_message_creator = PKIMessageCreator(pki_body, pki_header, pki_body_type, response_protection)
        return pki_message_creator.create_pki_message()

