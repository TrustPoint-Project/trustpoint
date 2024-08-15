from __future__ import annotations

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc4210
import logging

from pki.models import DomainModel
from pki.pki.cmp.validator.header_validator import GenericHeaderValidator
from pki.pki.cmp.validator.initialization_req_validator import InitializationReqValidator
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    Protocol,
    MimeType,
    HttpStatusCode,
    Operation)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    from pyasn1.type.base import Asn1Type
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class CmpOperation(Operation):
    INITIALIZATION_REQUEST = 'ir'


class PkiCmpInitializationRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.INITIALIZATION_REQUEST,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        try:
            self._init_mimetype(mimetype)
        except ValueError:
            return

        self._content_transfer_encoding = None

        try:
            self._init_domain_model(domain_unique_name)
        except ValueError:
            return

        try:
            self._init_raw_request(raw_request)
        except ValueError:
            return

        # TODO: check domain configurations, if protocol and operation are enabled

    def _init_mimetype(self, mimetype: None | str) -> None:
        try:
            self._mimetype = MimeType(mimetype)
            if self._mimetype != MimeType.APPLICATION_PKIXCMP:
                raise ValueError
        except ValueError:
            self._build_wrong_mimetype_response(mimetype)
            self._is_valid = False
            raise ValueError

    def _build_wrong_mimetype_response(self, received_mimetype: None | str = None) -> None:
        # TODO: Build CMP error message -> raw_message
        if received_mimetype is None:
            error_msg = (
                f'Request is missing a MimeType (ContentType). '
                f'Expected MimeType {MimeType.APPLICATION_PKIXCMP.value}.')
        else:
            error_msg = (
                f'Expected MimeType {MimeType.APPLICATION_PKIXCMP.value}, but received {received_mimetype}.')

        self.logger.error(error_msg)
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.UNSUPPORTED_MEDIA_TYPE,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def _init_domain_model(self, domain_unique_name: str) -> None:
        try:
            self._domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
        except DomainModel.DoesNotExist:
            self._build_domain_does_not_exist()
            self._is_valid = False
            raise ValueError

    def _build_domain_does_not_exist(self) -> None:
        # TODO: Build CMP error message -> raw_message
        error_msg = f'Domain {self._domain_unique_name} does not exist.'
        self.logger.error(error_msg)
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def _init_raw_request(self, raw_request: bytes) -> None:
        try:
            loaded_request, _ = decoder.decode(raw_request, asn1Spec=rfc4210.PKIMessage())
        except ValueError:
            self._build_malformed_cmp_response()
            self._is_valid = False
            raise ValueError

        try:
            header = loaded_request.getComponentByName('header')
            validate_header = GenericHeaderValidator(header)
            validate_header.validate()

            body = loaded_request.getComponentByName('body')
            validator = InitializationReqValidator(body)
            validator.validate()

        except ValueError:
            self._build_not_ir_message_response()
            self._is_valid = False
            raise ValueError

        self._cmp = loaded_request

    def _build_malformed_cmp_response(self) -> None:
        # TODO: Build CMP error message -> raw_message
        error_msg = f'The formal ASN.1 syntax of the whole message is not compliant with the definitions given in CMP'
        self.logger.error(error_msg)
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    def _build_not_ir_message_response(self) -> None:
        # TODO: Build CMP error message -> wrong header or body
        error_msg = f'CMP message (header & body) does not comply with RFC 9483.'
        self.logger.error(error_msg)
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.APPLICATION_PKIXCMP)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp
