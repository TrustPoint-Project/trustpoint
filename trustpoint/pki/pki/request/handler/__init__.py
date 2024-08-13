from __future__ import annotations

import abc

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.pki.request.message import PkiResponseMessage


class CaRequestHandler(abc.ABC):

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass
