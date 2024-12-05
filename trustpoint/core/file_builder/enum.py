from __future__ import annotations


import enum


__all__ = [
    'ArchiveFormat',
    'CertificateFileFormat'
]


class ArchiveFormat(enum.Enum):

    ZIP: str = ('zip', 'application/zip', '.zip')
    TAR_GZ: str = ('tar_gz', 'application/gzip', '.tar.gz')

    def __new__(cls, value: str, mime_type: str, file_extension: str) -> ArchiveFormat:
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj



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
