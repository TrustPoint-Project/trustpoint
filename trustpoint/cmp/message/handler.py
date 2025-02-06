from __future__ import annotations

import abc
from pyasn1_modules import rfc4210


class BaseHandler(abc.ABC):

    def process(self, context: rfc4210.PKIMessage) -> BaseHandler:
        pass