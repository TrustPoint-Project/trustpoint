from __future__ import annotations

from pki.pki.request.handler import est, cmp
from pki.issuing_ca import UnprotectedLocalIssuingCa
from pki.pki.request.message.est import PkiEstSimpleEnrollRequestMessage
from pki.pki.request.message.cmp import PkiCmpInitializationRequestMessage

from typing import TYPE_CHECKING

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
