from __future__ import annotations


from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.views import View


from pki.pki.request.message.cmp import PkiCmpInitializationRequestMessage
from pki.pki.request.handler.factory import CaRequestHandlerFactory


@method_decorator(csrf_exempt, name='dispatch')
class CmpInitializationRequestView(View):
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):

        # TODO: content-length
        pki_request = PkiCmpInitializationRequestMessage(
            mimetype=request.headers.get('Content-Type'),
            content_transfer_encoding=request.headers.get('Content-Transfer-Encoding'),
            domain_unique_name=self.kwargs.get('domain'),
            raw_request=request.read()
        )

        if pki_request.is_invalid:
            return pki_request.invalid_response.to_django_http_response()

        request_handler = CaRequestHandlerFactory.get_request_handler(pki_request)
        return request_handler.process_request().to_django_http_response()
