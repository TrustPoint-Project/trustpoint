from __future__ import annotations

import abc
import enum
from typing import TYPE_CHECKING, Annotated

from django.http import HttpResponse

from pki.models import DomainModel

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    from annotated_types import Ge
    from typing import Any


class PkiMessageValidationError(Exception):
    """Raised when a PKI message validation fails."""
    pass


class MimeType(enum.Enum):

    TEXT_PLAIN = 'text/plain; charset=utf-8'
    APPLICATION_PKCS7 = 'application/pkcs7'
    APPLICATION_PKCS7_CERTS_ONLY = 'application/pkcs7-mime; smime-type=certs-only'
    APPLICATION_PKCS8 = 'application/pkcs8'
    APPLICATION_PKCS10 = 'application/pkcs10'
    APPLICATION_PKCS12 = 'application/x-pkcs12'
    APPLICATION_CSRATTRS = 'application/csrattrs'
    APPLICATION_PKIXCMP = 'application/pkixcmp'
    MULTIPART_MIXED = 'multipart/mixed'
    MULTIPART_MIXED_BOUNDARY = 'multipart/mixed; boundary=estServerExampleBoundary'


class ContentTransferEncoding(enum.Enum):
    BASE64 = 'base64'


class HttpStatusCode(enum.Enum):
    OK = 200
    BAD_REQUEST = 400
    UNSUPPORTED_MEDIA_TYPE = 415


class PkiRequestMessage(abc.ABC):
    _domain_model: DomainModel
    _raw_content: None | bytes
    _parsed_content: Any

    _mimetype: None | MimeType = None
    _content_transfer_encoding: None | ContentTransferEncoding = None
    _content_length_max: None | Annotated[int, Ge(0)] = None

    _is_valid: bool = False
    _error_response: None | PkiResponseMessage = None

    def __init__(
            self,
            domain_model: DomainModel,
            raw_content: None | bytes,
            received_mimetype: None | str | MimeType = None,
            received_content_transfer_encoding: None | str | ContentTransferEncoding = None) -> None:

        self._domain_model = domain_model
        self._raw_content = raw_content

        try:
            self._validate_mimetype(received_mimetype)
            self._validate_content_transfer_encoding(received_content_transfer_encoding)
            self._validate_content_length_max()
        except PkiMessageValidationError:
            return

        # noinspection PyBroadException
        try:
            self._parse_content()
            self._is_valid = True
            # TODO(AlexHx8472): Consider using a decorator to catch
            # TODO(AlexHx8472): any errors on _parse_content and raise PkiMessageValidationError
        except Exception:
            self._is_valid = False
            self._build_parsing_message_content_failed()

    @property
    def mimetype(self) -> MimeType:
        return self._mimetype

    @property
    def content_transfer_encoding(self) -> ContentTransferEncoding:
        return self._content_transfer_encoding

    @property
    def content_length(self) -> Annotated[int, Ge(0)]:
        if self.raw_content is None:
            return 0
        else:
            return len(self.raw_content)

    @property
    def domain_model(self) -> DomainModel:
        return self._domain_model

    @property
    def raw_content(self) -> None | bytes:
        return self._raw_content

    @property
    def parsed_content(self) -> Any:
        return self._parsed_content

    @property
    def is_valid(self) -> bool:
        return self._is_valid

    @property
    def error_response(self) -> PkiResponseMessage:
        return self._error_response

    def _validate_mimetype(self, received_mimetype: None | MimeType) -> None:
        if self.mimetype is None:
            return

        try:
            received_mimetype = MimeType(received_mimetype)
        except ValueError:
            self._build_wrong_mimetype_response(received_mimetype)
            raise PkiMessageValidationError

        if MimeType(received_mimetype) != self.mimetype:
            self._build_wrong_mimetype_response(received_mimetype)
            raise PkiMessageValidationError

    def _build_wrong_mimetype_response(self, received_mimetype: None | MimeType = None) -> None:
        if received_mimetype is None:
            error_msg = (
                f'Request is missing a MimeType (ContentType). '
                f'Expected MimeType {MimeType.APPLICATION_PKCS10.value}.')
        else:
            error_msg = (
                f'Expected MimeType {self.mimetype.value}, but received {received_mimetype.value}.')
        self._error_response = PkiPlainTextHttpErrorResponseMessage(error_msg)

    def _validate_content_transfer_encoding(self, received_content_transfer_encoding: None | ContentTransferEncoding) -> None:
        if self.content_transfer_encoding is None:
            return

        try:
            received_content_transfer_encoding = ContentTransferEncoding(received_content_transfer_encoding)
        except ValueError:
            self._build_unsupported_content_transfer_encoding_response(received_content_transfer_encoding)
            raise PkiMessageValidationError

        if received_content_transfer_encoding != self.content_transfer_encoding:
            self._build_unsupported_content_transfer_encoding_response(received_content_transfer_encoding)
            raise PkiMessageValidationError

    def _build_unsupported_content_transfer_encoding_response(
            self,
            received_content_transfer_encoding: None | ContentTransferEncoding = None) -> None:
        if received_content_transfer_encoding is None:
            error_msg = (
                f'Request is missing the Content-Transfer-Encoding header. '
                f'Expected {ContentTransferEncoding.BASE64.value}.')
        else:
            error_msg = (
                f'Expected base64 Content-Transfer-Encoding header, '
                f'but received {received_content_transfer_encoding.value}.')
        self._error_response = PkiPlainTextHttpErrorResponseMessage(error_msg)

    def _validate_content_length_max(self) -> None:
        content_length = self.content_length
        if content_length is None:
            return
        if content_length < self._content_length_max:
            self._build_message_content_too_large(content_length)
            raise PkiMessageValidationError

    def _build_message_content_too_large(self, content_length: Annotated[int, Ge(0)]) -> None:
        error_msg = (
            f'Received message contains {content_length} bytes, '
            f'but only messages up to {self._content_length_max} bytes are allowed to be processed.')
        self._error_response = PkiPlainTextHttpErrorResponseMessage(error_msg)

    @abc.abstractmethod
    def _parse_content(self) -> None:
        pass

    def _build_parsing_message_content_failed(self) -> None:
        error_msg = 'Failed to parse message. Seems to be corrupted.'
        self._error_response = PkiPlainTextHttpErrorResponseMessage(error_msg)



class PkiResponseMessage:
    _raw_response: str | bytes
    _http_status: HttpStatusCode
    _mimetype: MimeType

    def __init__(
            self,
            raw_response: str | bytes,
            http_status: HttpStatusCode,
            mimetype: MimeType) -> None:
        self._raw_response = raw_response
        self._http_status = http_status
        self._mimetype = mimetype

    @property
    def raw_response(self) -> bytes:
        return self._raw_response

    @property
    def http_status(self) -> HttpStatusCode:
        return self._http_status

    @property
    def mimetype(self) -> MimeType:
        return self._mimetype

    def to_django_http_response(self) -> HttpResponse:
        return HttpResponse(
            content=self.raw_response,
            status=self.http_status.value,
            content_type=self.mimetype.value)


class PkiPlainTextHttpErrorResponseMessage(PkiResponseMessage):
    _raw_response: str
    _http_status: HttpStatusCode = HttpStatusCode.BAD_REQUEST
    _mimetype: MimeType = MimeType.TEXT_PLAIN

    def __init__(self, raw_response: str) -> None:
        super().__init__(
            raw_response=raw_response,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)
