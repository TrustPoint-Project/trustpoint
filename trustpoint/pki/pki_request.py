from abc import ABC, abstractmethod


class PkiCertificateRequest(ABC):
    _domain: str
    _operation: str
    _request: bytes

    @abstractmethod
    @property
    def csr_available(self) -> bool:
        pass

    @property
    def operation(self) -> str:
        return self._operation

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def get_raw_request(self) -> bytes:
        pass
