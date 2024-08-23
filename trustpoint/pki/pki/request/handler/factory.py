from __future__ import annotations

from pki.pki.request.handler import est, cmp, rest
from pki.issuing_ca import UnprotectedLocalIssuingCa
from pki.pki.request.message.est import PkiEstSimpleEnrollRequestMessage

from pki.pki.request.message.cmp import PkiCmpInitializationRequestMessage, PkiCmpRevocationRequestMessage, \
    PkiCmpGetRootUpdateRequestMessage, PkiCmpGetCrlsRequestMessage, PkiCmpGetCertReqTemplateRequestMessage, \
    PkiCmpGetCaCertsRequestMessage, PkiCmpCertificationRequestMessage, PkiCmpKeyUpdateRequestMessage

from pki.pki.request.message.rest import PkiRestCsrRequestMessage, PkiRestPkcs12RequestMessage

from typing import TYPE_CHECKING
import traceback

if TYPE_CHECKING:
    from pki.pki.request.handler import CaRequestHandler
    from pki.pki.request.message import PkiRequestMessage


class CaRequestHandlerFactory:

    @classmethod
    def get_request_handler(cls, request: PkiRequestMessage) -> CaRequestHandler:

        if isinstance(request.domain_model.issuing_ca.get_issuing_ca(), UnprotectedLocalIssuingCa):
            if isinstance(request, PkiEstSimpleEnrollRequestMessage):
                return est.LocalEstCaSimpleEnrollRequestHandler(request)

            if isinstance(request, PkiCmpInitializationRequestMessage):
                return cmp.LocalCmpInitializationRequestHandler(request)

            if isinstance(request, PkiCmpCertificationRequestMessage):
                print("TRIGGER")
                return cmp.LocalCmpCertificationRequestHandler(request)

            if isinstance(request, PkiCmpKeyUpdateRequestMessage):
                return cmp.LocalCmpKeyUpdateRequestHandler(request)

            if isinstance(request, PkiCmpRevocationRequestMessage):
                return cmp.LocalCmpRevocationRequestHandler(request)

            if isinstance(request, PkiCmpGetRootUpdateRequestMessage):
                return cmp.LocalCmpGetRootUpdateHandler(request)

            if isinstance(request, PkiCmpGetCertReqTemplateRequestMessage):
                return cmp.LocalCmpGetCertReqTemplateHandler(request)

            if isinstance(request, PkiCmpGetCaCertsRequestMessage):
                return cmp.LocalCmpGetCaCertsHandler(request)

            if isinstance(request, PkiCmpGetCrlsRequestMessage):
                return cmp.LocalCmpGetCrlsHandler(request)
            
            if isinstance(request, PkiRestCsrRequestMessage):
                return rest.LocalCaRestCsrRequestHandler(request)
            
            if isinstance(request, PkiRestPkcs12RequestMessage):
                return rest.LocalCaRestPkcs12RequestHandler(request)


        exc_msg = f'No suitable handler available for PKI request {request}'
        raise NotImplementedError