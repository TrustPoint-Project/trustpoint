from __future__ import annotations


import base64
from cryptography import x509

from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    PkiResponseMessage,
    MimeType,
    ContentTransferEncoding,
    HttpStatusCode)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


#
# class PkiEstSimpleEnrollRequestMessage(PkiRequestMessage):
#     _csr = x509.CertificateSigningRequest
#
#     def __init__(self,
#                  mimetype: None | str,
#                  content_transfer_encoding: None | str,
#                  domain_unique_name: str,
#                  raw_request: bytes):
#         super().__init__(
#             protocol=Protocols.EST,
#             operation=EstOperation.SIMPLE_ENROLL,
#             domain_unique_name=domain_unique_name)
#
#         try:
#             self._init_mimetype(mimetype)
#         except ValueError:
#             return
#
#         try:
#             self._init_content_transfer_encoding(content_transfer_encoding)
#         except ValueError:
#             return
#
#         try:
#             self._init_domain_model(domain_unique_name)
#         except ValueError:
#             return
#
#         try:
#             self._init_raw_request(raw_request)
#         except ValueError:
#             return
#
#         # TODO: check domain configurations, if protocol and operation are enabled
#
#     def _init_mimetype(self, mimetype: None | str) -> None:
#         try:
#             self._mimetype = MimeType(mimetype)
#             if self._mimetype != MimeType.APPLICATION_PKCS10:
#                 raise ValueError
#         except ValueError:
#             self._build_wrong_mimetype_response(mimetype)
#             self._is_valid = False
#             raise ValueError
#
#     def _init_content_transfer_encoding(self, content_transfer_encoding: None | str) -> None:
#         try:
#             self._content_transfer_encoding = ContentTransferEncoding(content_transfer_encoding)
#             if self._content_transfer_encoding != ContentTransferEncoding.BASE64:
#                 raise ValueError
#         except ValueError:
#             self._build_unsupported_content_transfer_encoding_response(content_transfer_encoding)
#             self._is_valid = False
#             raise ValueError
#
#     def _init_domain_model(self, domain_unique_name: str) -> None:
#         try:
#             self._domain_model = DomainModel.objects.get(unique_name=domain_unique_name)
#         except DomainModel.DoesNotExist:
#             self._build_domain_does_not_exist()
#             self._is_valid = False
#             raise ValueError
#
#     def _init_raw_request(self, raw_request: bytes) -> None:
#         # TODO: use serializer
#         try:
#             raw_request = base64.b64decode(raw_request)
#             self._csr = x509.load_der_x509_csr(raw_request)
#         except ValueError:
#             self._build_malformed_csr_response()
#             self._is_valid = False
#             raise ValueError
#
#     def _build_wrong_mimetype_response(self, received_mimetype: None | str = None) -> None:
#         if received_mimetype is None:
#             error_msg = (
#                 f'Request is missing a MimeType (ContentType). '
#                 f'Expected MimeType {MimeType.APPLICATION_PKCS10.value}.')
#         else:
#             error_msg = (
#                 f'Expected MimeType {MimeType.APPLICATION_PKCS10.value}, but received {received_mimetype}.')
#         self._invalid_response = PkiResponseMessage(
#             raw_response=error_msg,
#             http_status=HttpStatusCode.UNSUPPORTED_MEDIA_TYPE,
#             mimetype=MimeType.TEXT_PLAIN)
#
#     def _build_unsupported_content_transfer_encoding_response(
#             self,
#             content_transfer_encoding: None | str = None) -> None:
#         if content_transfer_encoding is None:
#             error_msg = (
#                 f'Request is missing the Content-Transfer-Encoding header. '
#                 f'Expected {ContentTransferEncoding.BASE64.value}.')
#         else:
#             error_msg = f'Expected base64 Content-Transfer-Encoding header, but received {content_transfer_encoding}.'
#         self._invalid_response = PkiResponseMessage(
#             raw_response=error_msg,
#             http_status=HttpStatusCode.BAD_REQUEST,
#             mimetype=MimeType.TEXT_PLAIN)
#
#     def _build_missing_csr_response(self) -> None:
#         error_msg = 'Missing CSR in EST Simple Enroll Request.'
#         self._invalid_response = PkiResponseMessage(
#             raw_response=error_msg,
#             http_status=HttpStatusCode.BAD_REQUEST,
#             mimetype=MimeType.TEXT_PLAIN)
#
#     def _build_malformed_csr_response(self) -> None:
#         error_msg = f'Failed to parse HTTP Body content. Does not seem to be a PKCS#10 CSR.'
#         self._invalid_response = PkiResponseMessage(
#             raw_response=error_msg,
#             http_status=HttpStatusCode.BAD_REQUEST,
#             mimetype=MimeType.TEXT_PLAIN)
#
#     def _build_domain_does_not_exist(self) -> None:
#         error_msg = f'Domain {self._domain_unique_name} does not exist.'
#         self._invalid_response = PkiResponseMessage(
#             raw_response=error_msg,
#             http_status=HttpStatusCode.BAD_REQUEST,
#             mimetype=MimeType.TEXT_PLAIN)
#
#     @property
#     def csr(self) -> x509.CertificateSigningRequest:
#         return self._csr



