from __future__ import annotations


from pyasn1.codec.der import decoder
from pyasn1_modules.rfc4210 import PKIMessage, PKIHeader
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.http import HttpResponse

from cmp.message.cmp import PkiMessageHeader, PkiMessageProtection, CertRequestMessages

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.http import HttpRequest

@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(View):

    http_method_names = ['post']

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:
        pass
        # content-length: 128kiB
        # content-type: application/pkixcmp
        # pki_message, _ = decoder.decode(request.read(), asn1Spec=PKIMessage())
        # pki_header = PkiMessageHeader(pki_message['header'])
        # pki_protection = PkiMessageProtection(pki_message['protection'])
        # pki_body = CertRequestMessages(pki_message['body'])
        # return HttpResponse(200)
