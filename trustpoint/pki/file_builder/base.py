from __future__ import annotations


import abc
import enum
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any


__all__ = [
    'CertificateFileContent',
    'CertificateFileFormat',
    'FileBuilder'
]


class CertificateFileFormat(enum.Enum):

    PEM: str = ('pem', 'application/x-pem-file', '.pem')
    DER: str = ('der', 'application/pkix-cert', '.cer')
    PKCS7_PEM: str = ('pkcs7_pem', 'application/x-pkcs7-certificates', '.p7b')
    PKCS7_DER: str = ('pkcs7_der', 'application/x-pkcs7-certificates', '.p7b')

    def __new__(cls, value: str, mime_type: str, file_extension: str) -> CertificateFileFormat:
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class CertificateFileContent(enum.Enum):

    CERT_ONLY: str = 'cert_only'
    CERT_AND_CHAIN: str = 'cert_and_chain'
    CHAIN_ONLY: str = 'chain_only'


class FileBuilder(abc.ABC):

    @staticmethod
    @abc.abstractmethod
    def build(*args: tuple[Any], **kwargs: dict[str, Any]) -> bytes:
        pass
