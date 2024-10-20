"""This package contains the views for all PKI protocol endpoints."""
from __future__ import annotations

import enum

from pki.models import DomainModel
from pki.pki.request.message import PkiResponseMessage, HttpStatusCode, MimeType

class PkiProtocol(enum.Enum):

    NONE = 'no_protocol'
    CMP = 'cmp_protocol'
    EST = 'est_protocol'
    SCEP = 'scep_protocol'
    REST = 'rest_protocol'
    ACME = 'acme_protocol'


class DomainHandler:

    _unique_name: str
    _pki_protocol: PkiProtocol
    _domain_model: None | DomainModel = None

    _is_valid: bool = False
    _error_response: None | PkiResponseMessage = None

    def __init__(self, unique_name: str, pki_protocol: PkiProtocol) -> None:
        self._unique_name = unique_name
        self._pki_protocol = pki_protocol

        self._domain_model = DomainModel.objects.filter(unique_name=unique_name).first()
        if self._domain_model is None:
            self._set_does_not_exist_response()
            return

        if pki_protocol == PkiProtocol.NONE:
            self._is_valid = True
            return

        pki_protocol_model = getattr(self.domain_model, self.pki_protocol.value, None)
        if pki_protocol_model is None:
            self._set_protocol_unknown_response()
            return

        if not pki_protocol_model.status:
            self._set_protocol_not_activated_response()
            return

        self._is_valid = True


    @property
    def unique_name(self) -> str:
        return self._unique_name

    @property
    def pki_protocol(self) -> PkiProtocol:
        return self._pki_protocol

    @property
    def domain_model(self) -> None | DomainModel:
        return self._domain_model

    def is_valid(self) -> bool:
        return self._is_valid

    @property
    def error_response(self) -> None | PkiResponseMessage:
        return self._error_response

    def _set_does_not_exist_response(self) -> None:
        self._error_response = PkiResponseMessage(
            raw_response=f'Domain {self.unique_name} does not exist.',
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _set_protocol_unknown_response(self) -> None:
        err_msg = f'Unknown PKI protocol found for Domain {self.unique_name}.'
        self._error_response = PkiResponseMessage(
            raw_response=err_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)

    def _set_protocol_not_activated_response(self) -> None:
        err_msg = f'Domain {self.unique_name} does not allow any requests using the {self.pki_protocol.name} exist.'
        self._error_response = PkiResponseMessage(
            raw_response=err_msg,
            http_status=HttpStatusCode.BAD_REQUEST,
            mimetype=MimeType.TEXT_PLAIN)
