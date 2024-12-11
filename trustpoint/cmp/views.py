from __future__ import annotations


from pyasn1.codec.der import decoder
from pyasn1_modules.rfc4210 import PKIMessage
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.http import HttpResponse

from cmp.message.cmp import PkiIrMessage

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.http import HttpRequest

@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(View):

    http_method_names = ['post']

    def post(self, *args: tuple, **kwargs: dict) -> HttpResponse:

        # content-length: 128kiB
        # content-type: application/pkixcmp
        pki_message, _ = decoder.decode(self.request.read(), asn1Spec=PKIMessage())
        pki_message = PkiIrMessage(pki_message)


        print(pki_message.request_template.subject)
        print(pki_message.request_template.public_key)
        print(pki_message.request_template.not_valid_before)
        print(pki_message.request_template.not_valid_after)


        return HttpResponse(200)
