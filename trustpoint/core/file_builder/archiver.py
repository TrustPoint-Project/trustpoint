"""Module that contains utilities to construct different archives from lists of bytes."""

from __future__ import annotations

import io
import tarfile
import zipfile

from core.file_builder.enum import ArchiveFormat


class Archiver:
    """Provides methods to construct different archives."""

    @classmethod
    def archive(cls, data_to_archive: dict[str, bytes], archive_format: ArchiveFormat) -> bytes:
        """Creates an archive with the given format.

        Args:
            data_to_archive: Data to archive. Will use the key as filename.
            archive_format: The archive format to use.

        Returns:
            bytes: The binary representation of the archive.
        """
        if archive_format == ArchiveFormat.ZIP:
            return cls.archive_zip(data_to_archive)
        if archive_format == ArchiveFormat.TAR_GZ:
            return cls.archive_tar_gz(data_to_archive)

        err_msg = f'Unknown archive format: {archive_format.value}.'
        raise ValueError(err_msg)

    @staticmethod
    def archive_zip(data_to_archive: dict[str, bytes]) -> bytes:
        """Creates a zip-archive.

        Args:
            data_to_archive: Data to archive. Will use the key as filename.

        Returns:
            bytes: The binary representation of the archive.
        """
        bytes_io = io.BytesIO()
        zip_file = zipfile.ZipFile(bytes_io, 'w')
        for file_name, bytes_blob in data_to_archive.items():
            zip_file.writestr(file_name, bytes_blob)
        zip_file.close()

        return bytes_io.getvalue()

    @staticmethod
    def archive_tar_gz(data_to_archive: dict[str, bytes]) -> bytes:
        """Creates a tar-gz-archive.

        Args:
            data_to_archive: Data to archive. Will use the key as filename.

        Returns:
            bytes: The binary representation of the archive.
        """
        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for file_name, cert_bytes in data_to_archive.items():
                cert_io_bytes = io.BytesIO(cert_bytes)
                cert_io_bytes_info = tarfile.TarInfo(file_name)
                cert_io_bytes_info.size = len(cert_bytes)
                tar.addfile(cert_io_bytes_info, cert_io_bytes)

        return bytes_io.getvalue()
