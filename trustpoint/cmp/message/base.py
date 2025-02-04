from __future__ import annotations


from cryptography import x509
from pyasn1_modules import rfc4210

class CmpHeader:
    pass

class CmpBody:
    pass

class CmpProtection:
    pass

class CmpExtraCerts:
    pass


class CmpMessage(CmpHeader, CmpBody, CmpProtection, CmpExtraCerts):

    _cmp_asn1_message: rfc4210.PKIMessage

    def __init__(self, cmp_asn1_message: rfc4210.PKIMessage) -> None:
        self._cmp_asn1_message = cmp_asn1_message
        super().__init__()

