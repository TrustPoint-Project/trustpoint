from __future__ import annotations
from typing import TYPE_CHECKING
from abc import ABC
from enum import Enum


from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
from cryptography import x509


if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    Operation = Union['EstOperation']


class EstOperation(Enum):

    SIMPLE_ENROLL = 'simple_enroll'


class PkiProtocol(Enum):

    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'


class PkiRequestMessage(ABC):
    # TODO: Validators
    _private_key: None | PrivateKey = None
    _operation: Operation
    _domain: str
    _protocol: PkiProtocol
    _raw_request: bytes

    def __init__(
            self,
            operation: Operation,
            domain: str,
            protocol: PkiProtocol,
            raw_request: bytes,
            *args,
            **kwargs) -> None:
        self._operation = operation
        self._domain = domain
        self._protocol = protocol
        self._raw_request = raw_request

    @property
    def operation(self) -> Operation:
        return self._operation

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def protocol(self) -> PkiProtocol:
        return self._protocol

    @property
    def raw_request(self) -> bytes:
        return self._raw_request


class PkiEstRequestMessage(PkiRequestMessage):
    _csr: None | x509.CertificateSigningRequest = None

    def __init__(
            self,
            operation: Operation,
            domain: str,
            raw_request: bytes,
            *args,
            **kwargs) -> None:
        super().__init__(
            operation=operation,
            domain=domain,
            protocol=PkiProtocol.EST,
            raw_request=raw_request,
            args=args,
            kwargs=kwargs)

    @property
    def csr(self) -> x509.CertificateSigningRequest:
        if self._csr is None:
            self._csr = x509.load_pem_x509_csr(self._raw_request)
        return self._csr


class PkiCmpRequestMessage(PkiRequestMessage):
    pass


class PkiRestRequestMessage(PkiRequestMessage):
    pass


class PkiResponseMessage:
    pass


class PkiEstResponseMessage(PkiResponseMessage):
    _raw_response: bytes
    _http_status: int
    _mimetype: str

    def __init__(self, response: bytes, http_status: int, mimetype: str) -> None:
        self._raw_response = response
        self._http_status = http_status
        self._mimetype = mimetype

    @property
    def raw_response(self) -> bytes:
        return self._raw_response

    @property
    def http_status(self) -> int:
        return self._http_status

    @property
    def mimetype(self) -> str:
        return self._mimetype
