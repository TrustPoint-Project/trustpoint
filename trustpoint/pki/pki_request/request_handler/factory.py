from __future__ import annotations


from typing import TYPE_CHECKING

from ..message import PkiRequestMessage
from ..message.est import PkiEstSimpleEnrollRequestMessage


from ...issuing_ca import UnprotectedLocalIssuingCa
from . import est


if TYPE_CHECKING:
    from . import CaRequestHandler


class CaRequestHandlerFactory:

    @classmethod
    def get_request_handler(cls, request: PkiRequestMessage) -> CaRequestHandler:

        if isinstance(request, PkiEstSimpleEnrollRequestMessage):
            if isinstance(request.domain_model.issuing_ca.get_issuing_ca(), UnprotectedLocalIssuingCa):
                return est.LocalEstCaSimpleEnrollRequestHandler(request)