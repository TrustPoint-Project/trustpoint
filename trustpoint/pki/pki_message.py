from __future__ import annotations
from typing import TYPE_CHECKING
import abc
from enum import Enum
import base64
from django.http import HttpResponse


from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
from cryptography import x509
from .models import DomainModel


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class Operation(Enum):
    pass


class EstOperation(Operation):
    SIMPLE_ENROLL = 'simple_enroll'


class MimeType(Enum):

    TEXT_PLAIN = 'text/plain; charset=utf-8'
    APPLICATION_PKCS7 = 'application/pkcs7'
    APPLICATION_PKCS7_CERTS_ONLY = 'application/pkcs7-mime; smime-type=certs-only'
    APPLICATION_PKCS8 = 'application/pkcs8'
    APPLICATION_PKCS10 = 'application/pkcs10'
    APPLICATION_CSRATTRS = 'application/csrattrs'
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


class PkiEstSimpleEnrollRequestMessage(PkiRequestMessage):
    _csr = x509.CertificateSigningRequest

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.EST,
            operation=EstOperation.SIMPLE_ENROLL,
            domain_unique_name=domain_unique_name)

        try:
            self._init_mimetype(mimetype)
        except ValueError:
            return

        try:
            self._init_content_transfer_encoding(content_transfer_encoding)
        except ValueError:
            return

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
            if self._mimetype != MimeType.APPLICATION_PKCS10:
                raise ValueError
        except ValueError:
            self._build_wrong_mimetype_response(mimetype)
            self._is_valid = False
            raise ValueError

    def _init_content_transfer_encoding(self, content_transfer_encoding: None | str) -> None:
        try:
            self._content_transfer_encoding = ContentTransferEncoding(content_transfer_encoding)
            if self._content_transfer_encoding != ContentTransferEncoding.BASE64:
                raise ValueError
        except ValueError:
            self._build_unsupported_content_transfer_encoding_response(content_transfer_encoding)
            self._is_valid = False
            raise ValueError

    def _init_domain_model(self, domain_unique_name: str) -> None:
        try:
            self._domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
        except DomainModel.DoesNotExist:
            self._build_domain_does_not_exist()
            self._is_valid = False
            raise ValueError

    def _init_raw_request(self, raw_request: bytes) -> None:
        # TODO: use serializer
        try:
            raw_request = base64.b64decode(raw_request)
            self._csr = x509.load_der_x509_csr(raw_request)
        except ValueError:
            self._build_malformed_csr_response()
            self._is_valid = False
            raise ValueError

    def _build_wrong_mimetype_response(self, received_mimetype: None | str = None) -> None:
        if received_mimetype is None:
            error_msg = (
                f'Request is missing a MimeType (ContentType). '
                f'Expected MimeType {MimeType.APPLICATION_PKCS10.value}.')
        else:
            error_msg = (
                f'Expected MimeType {MimeType.APPLICATION_PKCS10.value}, but received {received_mimetype}.')
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.UNSUPPORTED_MEDIA_TYPE,
            mimetype=MimeType.TEXT_PLAIN)

    def _build_unsupported_content_transfer_encoding_response(
            self,
            content_transfer_encoding: None | str = None) -> None:
        if content_transfer_encoding is None:
            error_msg = (
                f'Request is missing the Content-Transfer-Encoding header. '
                f'Expected {ContentTransferEncoding.BASE64.value}.')
        else:
            error_msg = f'Expected base64 Content-Transfer-Encoding header, but received {content_transfer_encoding}.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _build_missing_csr_response(self) -> None:
        error_msg = 'Missing CSR in EST Simple Enroll Request.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _build_malformed_csr_response(self) -> None:
        error_msg = f'Failed to parse HTTP Body content. Does not seem to be a PKCS#10 CSR.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _build_domain_does_not_exist(self) -> None:
        error_msg = f'Domain {self._domain_unique_name} does not exist.'
        self._invalid_response = PkiResponseMessage(
            raw_response=error_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    @property
    def csr(self) -> x509.CertificateSigningRequest:
        return self._csr


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
