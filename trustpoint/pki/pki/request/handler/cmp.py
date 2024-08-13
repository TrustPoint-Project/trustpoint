from __future__ import annotations

import abc
import datetime

from pki.pki.request.handler import CaRequestHandler

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message import PkiResponseMessage
    from pki.pki.request.message.cmp import PkiCmpInitializationRequestMessage
    from pki.issuing_ca import UnprotectedLocalIssuingCa


ONE_DAY = datetime.timedelta(1, 0, 0)


class CaCmpRequestHandler(CaRequestHandler):

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass


class LocalCmpInitializationRequestHandler(CaCmpRequestHandler):
    _request_message: PkiCmpInitializationRequestMessage
    _issuing_ca: UnprotectedLocalIssuingCa

    def __init__(self, request: PkiCmpInitializationRequestMessage):
        self._request_message = request
        self._issuing_ca = self._request_message.domain_model.issuing_ca.get_issuing_ca()

    # TODO: Validation if Certificate is allowed to be issued
    # TODO: check if certificate was already issued etc.
    # TODO: Store issued certificate in DB
    def process_request(self) -> PkiResponseMessage:
        pass
