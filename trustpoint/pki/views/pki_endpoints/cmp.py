from __future__ import annotations

import traceback

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


from django.views import View

from pki.views.pki_endpoints import PkiProtocol, DomainHandler
from pki.pki.request.handler.factory import CaRequestHandlerFactory
from pki.pki.request.message.cmp import (
    PkiCmpInitializationRequestMessage,
    # PkiCmpRevocationRequestMessage,
    # PkiCmpGetRootUpdateRequestMessage,
    # PkiCmpGetCrlsRequestMessage,
    # PkiCmpGetCertReqTemplateRequestMessage,
    # PkiCmpGetCaCertsRequestMessage,
    # PkiCmpCertificationRequestMessage,
    # PkiCmpKeyUpdateRequestMessage
)

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from django.http import HttpResponse

@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(View):

    http_method_names = ['post']

    def post(self, request, *args, **kwargs) -> HttpResponse:
        domain_handler = DomainHandler(self.kwargs.get('domain'), PkiProtocol.CMP)
        if not domain_handler.is_valid():
            return domain_handler.error_response.to_django_http_response()

        pki_request = PkiCmpInitializationRequestMessage(
            domain_model=domain_handler.domain_model,
            raw_content=request.read(),
            received_mimetype=request.headers.get('Content-Type'),
            received_content_transfer_encoding=request.headers.get('Content-Transfer-Encoding')
        )

        if not pki_request.is_valid:
            return pki_request.error_response.to_django_http_response()

        request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
        return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpCertificationRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpCertificationRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpKeyUpdateRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpKeyUpdateRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpPkcs10RequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpInitializationRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpRevocationRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpRevocationRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpGetCaCertsRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpGetCaCertsRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpGetRootUpdateRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpGetRootUpdateRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpGetCertReqTemplateRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpGetCertReqTemplateRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()
#
# @method_decorator(csrf_exempt, name='dispatch')
# class CmpGetCrlsRequestView(View):
#     http_method_names = ['post']
#
#     def post(self, request, *args, **kwargs):
#
#         # TODO: content-length
#         pki_request = PkiCmpGetCrlsRequestMessage(
#             mimetype=request.headers.get('Content-Type'),
#             content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
#             domain_unique_name=self.kwargs.get('domain'),
#             raw_request=request.read()
#         )
#
#         if pki_request.is_invalid:
#             return pki_request.invalid_response.to_django_http_response()
#
#         request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
#         return request_handler.process_request().to_django_http_response()