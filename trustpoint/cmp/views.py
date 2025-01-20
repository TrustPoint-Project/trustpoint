from __future__ import annotations


from pyasn1.codec.der import decoder
from pyasn1_modules.rfc4210 import PKIMessage
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.http import HttpResponse

from cmp.message.cmp import PkiIrMessage

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from django.http import HttpRequest
    from typing import Any


class Dispatchable(Protocol):
    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        ...

class CmpHttpMixin(Dispatchable):

    expected_content_type = 'application/pkixcmp'
    content_length_required = True
    max_content_length = 128


    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # length_required -> 411
        # too large -> 413
        # wrong content_type -> 415
        return super().dispatch(request, *args, **kwargs)


class CmpValidDomainCheckMixin(Dispatchable):

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # check if Domain exists
        # check if Domain allows CMP and this operation
        return super().dispatch(request, *args, **kwargs)


class CmpMessageSerializerMixin(Dispatchable):

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        pki_message, _ = decoder.decode(request.read(), asn1Spec=PKIMessage())
        request.serialized_message = pki_message
        return super().dispatch(request, *args, **kwargs)


class CmpMessageTypeCheckMixin(Dispatchable):

    expected_message_type: str

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # check expected message type
        return super().dispatch(request, *args, **kwargs)


class CmpMessageAuthenticationMixin(Dispatchable):

    signature_based_ok: bool = True
    password_based_hmac: bool = False

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # authenticate
        return super().dispatch(request, *args, **kwargs)


class CmpAuthorizationMixin(Dispatchable):

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # check if the authenticated entity is generally allowed to use this operation.
        return super().dispatch(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(
    CmpHttpMixin,
    CmpValidDomainCheckMixin,
    CmpMessageSerializerMixin,
    CmpMessageTypeCheckMixin,
    CmpMessageAuthenticationMixin,
    View):

    http_method_names = ('post',)
    expected_message_type = 'ir'

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:

        # Get certificate request parameters.
        # Check certificate request parameters -> further authorization.
        # Execute operation.



        # content-length: 128kiB
        # content-type: application/pkixcmp
        # pki_message, _ = decoder.decode(self.request.read(), asn1Spec=PKIMessage())
        # pki_message = PkiIrMessage(pki_message)
        #
        # print(pki_message.request_template.subject)
        # print(pki_message.request_template.public_key)
        # print(pki_message.request_template.not_valid_before)
        # print(pki_message.request_template.not_valid_after)

        return HttpResponse(200)
