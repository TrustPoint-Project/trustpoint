from __future__ import annotations
from typing import TYPE_CHECKING
import abc
from enum import Enum
from django.http import HttpResponse


from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
from ...models import DomainModel


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Operation(Enum):
    pass


class MimeType(Enum):

    TEXT_PLAIN = 'text/plain; charset=utf-8'
    APPLICATION_PKCS7 = 'application/pkcs7'
    APPLICATION_PKCS7_CERTS_ONLY = 'application/pkcs7-mime; smime-type=certs-only'
    APPLICATION_PKCS8 = 'application/pkcs8'
    APPLICATION_PKCS10 = 'application/pkcs10'
    APPLICATION_CSRATTRS = 'application/csrattrs'
    APPLICATION_PKIXCMP = 'application/pkixcmp'
    MULTIPART_MIXED = 'multipart/mixed'
    MULTIPART_MIXED_BOUNDARY = 'multipart/mixed; boundary=estServerExampleBoundary'


class ContentTransferEncoding(Enum):
    BASE64 = 'base64'


class HttpStatusCode(Enum):
    OK = 200
    BAD_REQUEST = 400
    UNSUPPORTED_MEDIA_TYPE = 415


class Protocol(Enum):

    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'


class PkiRequestMessage(abc.ABC):
    _protocol: Protocol
    _operation: Operation
    _mimetype: None | MimeType = None
    _content_transfer_encoding: None | ContentTransferEncoding = None
    _domain_unique_name: None | str = None
    _domain_model: None | DomainModel = None
    _raw_request: None | bytes = None
    _is_valid: bool = True
    _invalid_response: None | PkiResponseMessage = None

    def __init__(self, protocol: Protocol, operation: Operation, domain_unique_name: str) -> None:
        self._protocol = protocol
        self._operation = operation
        self._domain_unique_name = domain_unique_name

    @property
    def protocol(self) -> Protocol:
        return self._protocol

    @property
    def operation(self) -> Operation:
        return self._operation

    @property
    def mimetype(self) -> MimeType:
        return self._mimetype

    @property
    def content_transfer_encoding(self) -> ContentTransferEncoding:
        return self._content_transfer_encoding

    @property
    def domain_model(self) -> DomainModel:
        return self._domain_model

    @property
    def raw_request(self) -> bytes:
        return self._raw_request

    @property
    def is_valid(self) -> bool:
        return self._is_valid

    @property
    def is_invalid(self) -> bool:
        return not self.is_valid

    @property
    def invalid_response(self) -> PkiResponseMessage:
        return self._invalid_response


class PkiResponseMessage:
    _raw_response: str | bytes
    _http_status: HttpStatusCode
    _mimetype: MimeType

    def __init__(self, raw_response: str | bytes, http_status: HttpStatusCode, mimetype: MimeType) -> None:
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
