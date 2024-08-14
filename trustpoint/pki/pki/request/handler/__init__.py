from __future__ import annotations

import abc

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message import PkiRequestMessage, PkiResponseMessage


class CaRequestHandler(abc.ABC):

    def __init__(self, request: PkiRequestMessage):
        self._request_message = request
        self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass
