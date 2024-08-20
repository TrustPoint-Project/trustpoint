from __future__ import annotations

from pyasn1_modules import rfc4210
import logging

from pki.models import DomainModel
from pki.pki.request.message import (
    PkiRequestMessage,
    Protocol,
    Operation)

from typing import TYPE_CHECKING

from pki.pki.request.message.cmp_validator import CmpRequestMessageValidator

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
    from pyasn1.type.base import Asn1Type
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


class CmpOperation(Operation):
    INITIALIZATION_REQUEST = 'ir'
    CERTIFICATION_REQUEST = 'cr'
    KEYUPDATE_REQUEST = 'kur'
    REVOCATION_REQUEST = 'rr'
    GENERAL_MESSAGE = 'genm'

class PkiCmpInitializationRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes,
                 alias_unique_name: str):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.INITIALIZATION_REQUEST,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing PkiCmpInitializationRequestMessage for domain: %s", domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_initialization_request(mimetype, domain_unique_name, DomainModel, raw_request,
                                                                rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model
        self._alias_unique_name = alias_unique_name

        self._is_valid = self.validator.is_valid
        self.logger.info("PkiCmpInitializationRequestMessage initialized successfully for domain: %s",
                         domain_unique_name)
    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpCertificationRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.CERTIFICATION_REQUEST,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing PkiCmpCertificationRequestMessage for domain: %s", domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_certification_request(mimetype, domain_unique_name, DomainModel, raw_request,
                                                                rfc4210.PKIMessage())

        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("PkiCmpCertificationRequestMessage initialized successfully for domain: %s",
                         domain_unique_name)
    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpKeyUpdateRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.KEYUPDATE_REQUEST,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing PkiCmpKeyUpdateRequestMessage for domain: %s", domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_keyupdate_request(mimetype, domain_unique_name, DomainModel, raw_request,
                                                                rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("PkiCmpKeyUpdateRequestMessage initialized successfully for domain: %s",
                         domain_unique_name)
    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpRevocationRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.REVOCATION_REQUEST,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing %s for domain: %s", self.__class__.__name__, domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_revocation_request(mimetype, domain_unique_name, DomainModel, raw_request,
                                                                rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("%s initialized successfully for domain: %s", self.__class__.__name__,
                         domain_unique_name)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpGetRootUpdateRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.GENERAL_MESSAGE,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing %s for domain: %s", self.__class__.__name__, domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_general_message(mimetype, domain_unique_name, DomainModel, raw_request,
                                                            rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("%s initialized successfully for domain: %s", self.__class__.__name__,
                         domain_unique_name)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpGetCrlsRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.GENERAL_MESSAGE,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing %s for domain: %s", self.__class__.__name__, domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_general_message(mimetype, domain_unique_name, DomainModel, raw_request,
                                                            rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("%s initialized successfully for domain: %s", self.__class__.__name__,
                         domain_unique_name)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpGetCertReqTemplateRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.GENERAL_MESSAGE,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing %s for domain: %s", self.__class__.__name__, domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_general_message(mimetype, domain_unique_name, DomainModel, raw_request,
                                                            rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("%s initialized successfully for domain: %s", self.__class__.__name__,
                         domain_unique_name)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

class PkiCmpGetCaCertsRequestMessage(PkiRequestMessage):
    _cmp: Asn1Type

    def __init__(self,
                 mimetype: None | str,
                 content_transfer_encoding: None | str,
                 domain_unique_name: str,
                 raw_request: bytes):
        super().__init__(
            protocol=Protocol.CMP,
            operation=CmpOperation.GENERAL_MESSAGE,
            domain_unique_name=domain_unique_name)

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)

        self.logger.info("Initializing %s for domain: %s", self.__class__.__name__, domain_unique_name)

        self.validator = CmpRequestMessageValidator(self.logger)
        self._content_transfer_encoding = None

        result = self.validator.validate_general_message(mimetype, domain_unique_name, DomainModel, raw_request,
                                                            rfc4210.PKIMessage())
        if not result:
            self._invalid_response = self.validator.invalid_response
            self._is_valid = False
            self.logger.error("Validation failed during initialization.")
            return

        loaded_request, domain_model = result
        self._cmp = loaded_request
        self._domain_model = domain_model

        self._is_valid = self.validator.is_valid
        self.logger.info("%s initialized successfully for domain: %s", self.__class__.__name__,
                         domain_unique_name)

    @property
    def cmp(self) -> Asn1Type:
        return self._cmp

