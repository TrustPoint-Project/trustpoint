from __future__ import annotations

import abc
import datetime
import logging
from pyasn1.codec.der import decoder
from pyasn1_modules.rfc4210 import PKIMessage

from pki.pki.request.message import PkiResponseMessage, MimeType, HttpStatusCode
from pki.pki.request.handler import CaRequestHandler
from pki.pki.request.handler.messagehandler import CMPMessageHandler

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message.cmp import PkiCmpInitializationRequestMessage
    # , PkiCmpCertificationRequestMessage, PkiCmpKeyUpdateRequestMessage, PkiCmpRevocationRequestMessage, PkiCmpGetRootUpdateRequestMessage, PkiCmpGetCrlsRequestMessage, PkiCmpGetCertReqTemplateRequestMessage, PkiCmpGetCaCertsRequestMessage)
    from pki.issuing_ca import UnprotectedLocalIssuingCa
    from pki.pki.request.message import PkiRequestMessage


ONE_DAY = datetime.timedelta(1, 0, 0)


class CaCmpRequestHandler(CaRequestHandler):
    
    def __init__(self, request: PkiRequestMessage):
        super().__init__(request)        

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass


class LocalCmpInitializationRequestHandler(CaCmpRequestHandler):
    _request_message: PkiCmpInitializationRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def __init__(self, request: PkiCmpInitializationRequestMessage) -> None:
        super().__init__(request)
        self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()

        self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)

    # TODO: Validation if Certificate is allowed to be issued
    # TODO: check if certificate was already issued etc.
    def process_request(self) -> PkiResponseMessage:
        domain_model = self._request_message.domain_model

        # cert = domain_model.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
        # print(domain_model.issuing_ca.issuing_ca_certificate.issued_certificate_references)
        # authorized_clients = [cert]
        # shared_secret = b'foo123'

        # try:

        try:
            loaded_cmp_msg, _ = decoder.decode(self._request_message.raw_content, asn1Spec=PKIMessage())
        except Exception as exception:
            # TODO: differentiate parsing errors
            # TODO: return proper CMP Error Message
            return PkiResponseMessage(
                raw_response='Parsing the CMP Message failed.',
                http_status=HttpStatusCode.BAD_REQUEST,
                mimetype=MimeType.TEXT_PLAIN
            )
        cmp_message = CMPMessageHandler(pki_message=loaded_cmp_msg, operation='ir')
        cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
        # if authorized_clients:
        #     cmp_message.set_signature_based_protection(authorized_clients=[])
        #if shared_secret:
        #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
        encoded_response, http_status_code = cmp_message.process_request()

        return PkiResponseMessage(
            raw_response=encoded_response,
            http_status=http_status_code,
            mimetype=MimeType.APPLICATION_PKIXCMP)


# class LocalCmpCertificationRequestHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpCertificationRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpCertificationRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     def process_request(self) -> PkiResponseMessage:
#         self.logger.info('TESTE')
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         self.logger.info(self._request_message.cmp)
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='cr')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpKeyUpdateRequestHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpKeyUpdateRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpKeyUpdateRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='kur')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpRevocationRequestHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpInitializationRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpRevocationRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='rr')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpGetRootUpdateHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpGetRootUpdateRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpGetRootUpdateRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     # TODO: Store issued certificate in DB
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='genm')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpGetCrlsHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpGetCrlsRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpGetCrlsRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     # TODO: Store issued certificate in DB
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='genm')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpGetCertReqTemplateHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpGetCertReqTemplateRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpGetCertReqTemplateRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     # TODO: Store issued certificate in DB
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='genm')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())
#
# class LocalCmpGetCaCertsHandler(CaCmpRequestHandler):
#     _request_message: PkiCmpGetCaCertsRequestMessage
#     _issuing_ca: UnprotectedLocalIssuingCa
#
#     def __init__(self, request: PkiCmpGetCaCertsRequestMessage):
#         self._request_message = request
#         self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()
#
#         self.logger = logging.getLogger('tp').getChild(self.__class__.__name__)
#         self.logger.setLevel(logging.DEBUG)
#
#     # TODO: Validation if Certificate is allowed to be issued
#     # TODO: check if certificate was already issued etc.
#     # TODO: Store issued certificate in DB
#     def process_request(self) -> PkiResponseMessage:
#         domain = self._request_message.domain_model
#         cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
#         authorized_clients = [cert]
#         shared_secret = b'foo123'
#         try:
#             cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp, operation='genm')
#             cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
#             if authorized_clients:
#                 cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
#             #if shared_secret:
#             #    cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
#             encoded_response, http_status_code = cmp_message.process_request()
#
#             return PkiResponseMessage(
#                 raw_response=encoded_response,
#                 http_status=http_status_code,
#                 mimetype=MimeType.APPLICATION_PKIXCMP)
#         except Exception as e:
#             self.logger.error(traceback.format_exc())