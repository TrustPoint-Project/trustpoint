from __future__ import annotations

import abc
import datetime
import traceback
import logging

from pki.pki.request.message import PkiResponseMessage, MimeType
from pki.pki.cmp.messagehandler.cmp_message_handler import CMPMessageHandler
from pki.pki.request.handler import CaRequestHandler
import base64


from typing import TYPE_CHECKING

if TYPE_CHECKING:
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

        self.logger = logging.getLogger('tp')
        self.logger.setLevel(logging.DEBUG)


    # TODO: Validation if Certificate is allowed to be issued
    # TODO: check if certificate was already issued etc.
    # TODO: Store issued certificate in DB
    def process_request(self) -> PkiResponseMessage:
        domain = self._request_message.domain_model
        cert=domain.issuing_ca.issuing_ca_certificate.issued_certificate_references.first().get_certificate_serializer().as_crypto()
        authorized_clients = [cert]
        print(cert)
        try:
            cmp_message = CMPMessageHandler(pki_message=self._request_message.cmp)
            cmp_message.set_issuing_ca(issuing_ca_object=self._issuing_ca)
            if authorized_clients:
                cmp_message.set_signature_based_protection(authorized_clients=authorized_clients)
            # if shared_secret:
            #     cmp_message.set_pbm_based_protection(shared_secret=shared_secret)
            encoded_response, http_status_code = cmp_message.process_request()

            return PkiResponseMessage(
                raw_response=encoded_response,
                http_status=http_status_code,
                mimetype=MimeType.APPLICATION_PKIXCMP)
        except Exception as e:
            self.logger.error(traceback.format_exc())
