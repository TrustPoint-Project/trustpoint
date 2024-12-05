from __future__ import annotations


import io
import tarfile
import zipfile

from core.file_builder.enum import ArchiveFormat


class Archiver:

    @classmethod
    def archive(cls, data_to_archive: dict[str, bytes], archive_format: ArchiveFormat) -> bytes:
        if archive_format == ArchiveFormat.ZIP:
            return cls.archive_zip(data_to_archive)
        elif archive_format == ArchiveFormat.TAR_GZ:
            return cls.archive_tar_gz(data_to_archive)

        raise ValueError(f'Unknown archive format: {archive_format.value}.')

    @staticmethod
    def archive_zip(data_to_archive: dict[str, bytes]) -> bytes:
        bytes_io = io.BytesIO()
        zip_file = zipfile.ZipFile(bytes_io, 'w')
        for file_name, bytes_blob in data_to_archive.items():
            zip_file.writestr(file_name, bytes_blob)
        zip_file.close()

        return bytes_io.getvalue()

    @staticmethod
    def archive_tar_gz(data_to_archive: dict[str, bytes]) -> bytes:
        bytes_io = io.BytesIO()
        with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
            for file_name, cert_bytes in data_to_archive.items():
                cert_io_bytes = io.BytesIO(cert_bytes)
                cert_io_bytes_info = tarfile.TarInfo(file_name)
                cert_io_bytes_info.size = len(cert_bytes)
                tar.addfile(cert_io_bytes_info, cert_io_bytes)

        return bytes_io.getvalue()