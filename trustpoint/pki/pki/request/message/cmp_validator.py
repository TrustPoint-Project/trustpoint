import logging
import traceback

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210

from pki.pki.cmp.validator import (
    GeneralMessageValidator,
    GenericHeaderValidator,
    InitializationReqValidator,
    CertificateReqValidator,
    KeyUpdateReqValidator,
    RevocationReqValidator
)
from pki.pki.request.message import PkiResponseMessage, HttpStatusCode, MimeType


class CmpRequestMessageValidator:
    def __init__(self, logger):
        self.logger = logger
        self.invalid_response = None
        self._is_valid = True

    @property
    def is_valid(self):
        return self._is_valid

    def validate_mimetype(self, mimetype: str | None, expected_mimetype) -> bool:
        try:
            if mimetype is None or mimetype != expected_mimetype:
                raise ValueError
            return True
        except ValueError:
            self._build_wrong_mimetype_response(mimetype, expected_mimetype)
            self._is_valid = False
            return False

    def _build_wrong_mimetype_response(self, received_mimetype: None | str, expected_mimetype: str) -> None:
        if received_mimetype is None:
            error_msg = (
                f'Request is missing a MimeType (ContentType). '
                f'Expected MimeType {expected_mimetype}.')
        else:
            error_msg = (
                f'Expected MimeType {expected_mimetype}, but received {received_mimetype}.')

        self.logger.error(error_msg)
        self.invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            #http_status=HttpStatusCode.UNSUPPORTED_MEDIA_TYPE,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def validate_domain_model(self, domain_unique_name: str, DomainModel) -> bool:
        try:
            domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
            return domain_model
        except DomainModel.DoesNotExist:
            self._build_domain_does_not_exist(domain_unique_name)
            self._is_valid = False
            return None

    def _build_domain_does_not_exist(self, domain_unique_name: str) -> None:
        error_msg = f'Domain {domain_unique_name} does not exist.'
        self.logger.error(error_msg)
        self.invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            #http_status=HttpStatusCode.BAD_REQUEST,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def validate_raw_request(self, raw_request: bytes, asn1_spec) -> rfc4210.PKIMessage:
        try:
            loaded_request, _ = decoder.decode(raw_request, asn1Spec=asn1_spec)
            return loaded_request
        except ValueError:
            self._build_malformed_cmp_response()
            self._is_valid = False
            return None

    def _build_malformed_cmp_response(self) -> None:
        error_msg = f'The formal ASN.1 syntax of the whole message is not compliant with the definitions given in CMP'
        self.logger.error(error_msg)
        self.invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            #http_status=HttpStatusCode.BAD_REQUEST,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def validate_header(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            header = decoded_pki_message.getComponentByName('header')
            validate_header = GenericHeaderValidator(header)
            validate_header.validate()
            return True
        except Exception:
            self._build_malformed_cmp_header()
            self._is_valid = False
            return False


    def _build_malformed_cmp_header(self) -> None:
        error_msg = f'CMP header does not comply with RFC 9483.'
        self.logger.error(error_msg)
        self.logger.error(traceback.format_exc())
        self.invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            #http_status=HttpStatusCode.BAD_REQUEST,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def validate_initialization_body(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            body = decoded_pki_message.getComponentByName('body')
            validator = InitializationReqValidator(body)
            validator.validate()
            return True
        except Exception:
            self._build_malformed_cmp_body()
            self._is_valid = False
            return False

    def validate_certification_body(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            body = decoded_pki_message.getComponentByName('body')
            validator = CertificateReqValidator(body)
            validator.validate()
            return True
        except Exception:
            self._build_malformed_cmp_body()
            self._is_valid = False
            return False

    def validate_keyupdate_body(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            body = decoded_pki_message.getComponentByName('body')
            validator = KeyUpdateReqValidator(body)
            validator.validate()
            return True
        except Exception:
            self._build_malformed_cmp_body()
            self._is_valid = False
            return False

    def validate_revocation_req_body(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            body = decoded_pki_message.getComponentByName('body')
            validator = RevocationReqValidator(body)
            validator.validate()
            return True
        except Exception:
            self._build_malformed_cmp_body()
            self._is_valid = False
            return False

    def validate_general_message_body(self, decoded_pki_message: rfc4210.PKIMessage):
        try:
            body = decoded_pki_message.getComponentByName('body')
            validator = GeneralMessageValidator(body)
            validator.validate()
            return True
        except Exception:
            self._build_malformed_cmp_body()
            self._is_valid = False
            return False

    def _build_malformed_cmp_body(self) -> None:
        error_msg = f'CMP body does not comply with RFC 9483.'
        self.logger.error(error_msg)
        self.logger.error(traceback.format_exc())
        self.invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            #http_status=HttpStatusCode.BAD_REQUEST,
            http_status=HttpStatusCode.OK,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def _validate_generic_part(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):
        if not self.validate_mimetype(mimetype, MimeType.APPLICATION_PKIXCMP.value):
            return False

        domain_model = self.validate_domain_model(domain_unique_name, DomainModel)
        if not domain_model:
            return False

        loaded_request = self.validate_raw_request(raw_request, asn1_spec)
        if not loaded_request:
            return False

        if not self.validate_header(loaded_request):
            return False

        return loaded_request, domain_model

    def validate_initialization_request(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):
        result = self._validate_generic_part(mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec)
        if not result:
            return False


        loaded_request, domain_model = result

        if not self.validate_initialization_body(loaded_request):
            return False

        return loaded_request, domain_model

    def validate_certification_request(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):
        result = self._validate_generic_part(mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec)
        if not result:
            return False

        loaded_request, domain_model = result

        if not self.validate_certification_body(loaded_request):
            return False

        return loaded_request, domain_model

    def validate_keyupdate_request(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):
        result = self._validate_generic_part(mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec)
        if not result:
            return False

        loaded_request, domain_model = result

        if not self.validate_keyupdate_body(loaded_request):
            return False

        return loaded_request, domain_model
    def validate_revocation_request(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):

        result = self._validate_generic_part(mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec)
        if not result:
            return False

        loaded_request, domain_model = result

        if not self.validate_revocation_req_body(loaded_request):
            return False

        return loaded_request, domain_model

    def validate_general_message(self, mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec):
        self.logger.debug("Starting validation for CMP General Message.")

        result = self._validate_generic_part(mimetype, domain_unique_name, DomainModel, raw_request, asn1_spec)
        if not result:
            return False

        loaded_request, domain_model = result

        if not self.validate_general_message_body(loaded_request):
            return False

        self.logger.debug("CMP General Message validation completed successfully.")
        return loaded_request, domain_model



