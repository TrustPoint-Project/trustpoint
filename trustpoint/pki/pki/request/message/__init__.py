from __future__ import annotations

import abc
import enum
from typing import TYPE_CHECKING

from django.http import HttpResponse

from pki.models import CertificateModel, DomainModel
from pki.pki.request import Protocols

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Operation(enum.Enum):
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
    _protocol: Protocols
    _operation: Operation
    _mimetype: None | MimeType = None
    _content_transfer_encoding: None | ContentTransferEncoding = None
    _domain_unique_name: None | str = None
    _alias_unique_name: None | str = None
    _domain_model: None | DomainModel = None
    _raw_request: None | bytes = None
    _is_valid: bool = True
    _invalid_response: None | PkiResponseMessage = None

    def __init__(self, protocol: Protocols, operation: Operation, domain_unique_name: str) -> None:
        self._protocol = protocol
        self._operation = operation
        self._domain_unique_name = domain_unique_name

    def _init_domain_model(self, domain_unique_name: str) -> None:
        try:
            self._domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
        except DomainModel.DoesNotExist:
            self._build_domain_does_not_exist()
            self._is_valid = False
            raise ValueError
        
    def _build_domain_does_not_exist(self) -> None:
        error_msg = f'Domain {self._domain_unique_name} does not exist.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    @property
    def protocol(self) -> Protocols:
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

    @property
    def alias(self) -> str:
        return self._alias_unique_name


class PkiResponseMessage:
    _raw_response: str | bytes
    _http_status: HttpStatusCode
    _mimetype: MimeType
    _cert_model: None | CertificateModel = None

    def __init__(self, raw_response: str | bytes,
                 http_status: HttpStatusCode,
                 mimetype: MimeType,
                 cert_model: None | CertificateModel = None) -> None:
        self._raw_response = raw_response
        self._http_status = http_status
        self._mimetype = mimetype
        self._cert_model = cert_model

    @property
    def raw_response(self) -> bytes:
        return self._raw_response

    @property
    def http_status(self) -> HttpStatusCode:
        return self._http_status

    @property
    def mimetype(self) -> MimeType:
        return self._mimetype
    
    @property
    def cert_model(self) -> CertificateModel:
        return self._cert_model

    def to_django_http_response(self) -> HttpResponse:
        return HttpResponse(
            content=self.raw_response,
            status=self.http_status.value,
            content_type=self.mimetype.value)
