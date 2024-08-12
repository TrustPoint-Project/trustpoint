from __future__ import annotations

from typing import TYPE_CHECKING


import abc


if TYPE_CHECKING:
    from ..pki_message import PkiResponseMessage


class CaRequestHandler(abc.ABC):

    @abc.abstractmethod
    def process_request(self) -> PkiResponseMessage:
        pass
