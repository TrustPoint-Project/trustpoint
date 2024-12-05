from __future__ import annotations

from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from core.file_builder.base import  FileBuilder
from core.file_builder.archiver import Archiver
from pki.models import CertificateModel
from core.serializer import CertificateSerializer, CertificateCollectionSerializer

class CertificateFileBuilder(FileBuilder):

    @staticmethod
    def build(certificate_serializer: CertificateSerializer, file_format: CertificateFileFormat) -> bytes:

        if file_format == CertificateFileFormat.PEM:
            return certificate_serializer.as_pem()
        elif file_format == CertificateFileFormat.DER:
            return certificate_serializer.as_der()
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            return certificate_serializer.as_pkcs7_pem()
        elif file_format == CertificateFileFormat.PKCS7_DER:
            return certificate_serializer.as_pkcs7_der()

        raise ValueError(f'Unsupported file format: {file_format}.')


class CertificateArchiveFileBuilder(FileBuilder):

    @staticmethod
    def build(
            certificate_serializers: CertificateCollectionSerializer | list[CertificateSerializer],
            file_format: CertificateFileFormat,
            archive_format: ArchiveFormat) -> bytes:

        if isinstance(certificate_serializers, CertificateCollectionSerializer):
            certificate_serializers = certificate_serializers.as_certificate_serializer_list()

        if file_format == CertificateFileFormat.PEM:
            return Archiver.archive(
                data_to_archive = {
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pem()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_der()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pkcs7_pem()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.PKCS7_DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pkcs7_der()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format
            )

        raise ValueError(f'Unsupported file format: {file_format}.')
