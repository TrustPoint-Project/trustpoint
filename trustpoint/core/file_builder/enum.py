from __future__ import annotations


import enum


__all__ = [
    'ArchiveFormat',
    'CertificateFileFormat'
]


class ArchiveFormat(enum.Enum):

    mime_type: str
    file_extension: str

    ZIP: str = ('zip', 'application/zip', '.zip')
    TAR_GZ: str = ('tar_gz', 'application/gzip', '.tar.gz')

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> ArchiveFormat:
        if value is None:
            raise ValueError('None is not a valid archive format.')
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj



class CertificateFileFormat(enum.Enum):

    mime_type: str
    file_extension: str

    PEM: str = ('pem', 'application/x-pem-file', '.pem')
    DER: str = ('der', 'application/pkix-cert', '.cer')
    PKCS7_PEM: str = ('pkcs7_pem', 'application/x-pkcs7-certificates', '.p7b')
    PKCS7_DER: str = ('pkcs7_der', 'application/x-pkcs7-certificates', '.p7b')

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> CertificateFileFormat:
        if value is None:
            raise ValueError('None is not a valid file format.')
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj
