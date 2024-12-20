"""Module that contains enums concerning file types, file extensions, mimetypes and similar."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Self


__all__ = ['ArchiveFormat', 'CertificateFileFormat']


class ArchiveFormat(enum.Enum):
    """Supported archive formats."""

    mime_type: str
    file_extension: str

    ZIP: str = ('zip', 'application/zip', '.zip')  # type: ignore[assignment]
    TAR_GZ: str = ('tar_gz', 'application/gzip', '.tar.gz')  # type: ignore[assignment]

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> Self:
        """Extends the enum with a mime_type and file_extension.

        Args:
            value: The value to set.
            mime_type: The mime type to set.
            file_extension: The file extension to set.

        Returns:
            ArchiveFormat: The constructed enum.
        """
        if value is None:
            err_msg = 'None is not a valid archive format.'

            raise ValueError(err_msg)
        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class CertificateFileFormat(enum.Enum):
    """Supported certificate file formats"""

    mime_type: str
    file_extension: str

    PEM: str = ('pem', 'application/x-pem-file', '.pem')  # type: ignore[assignment]
    DER: str = ('der', 'application/pkix-cert', '.cer')  # type: ignore[assignment]
    PKCS7_PEM: str = ('pkcs7_pem', 'application/x-pkcs7-certificates', '.p7b')  # type: ignore[assignment]
    PKCS7_DER: str = ('pkcs7_der', 'application/x-pkcs7-certificates', '.p7b')  # type: ignore[assignment]

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> Self:
        """Extends the enum with a mime_type and file_extension.

        Args:
            value: The value to set.
            mime_type: The mime type to set.
            file_extension: The file extension to set.

        Returns:
            CertificateFileFormat: The constructed enum.
        """
        if value is None:
            err_msg = 'None is not a valid certificate file format.'
            raise ValueError(err_msg)

        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj
