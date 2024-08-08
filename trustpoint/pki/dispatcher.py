from .models import DomainModel
from .pki_message import PkiEstResponseMessage, PkiEstRequestMessage


class RequestDispatcher:

    @staticmethod
    def dispatch_est_request(request: PkiEstRequestMessage) -> PkiEstResponseMessage:
        domain_model = DomainModel.objects.filter(unique_name='Issuing CA').first()
        if not domain_model:
            return PkiEstResponseMessage(response=b'', http_status=111, mimetype='plain/text')
        return domain_model.process_est_request(request)
