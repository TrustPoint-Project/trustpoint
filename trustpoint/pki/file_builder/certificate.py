from __future__ import annotations

from . import CertificateFileContent, CertificateFileFormat, FileBuilder
from core.serializer import CertificateSerializer, CertificateCollectionSerializer
from pki.models import CertificateModel
from core.archiver import ArchiveFormat, Archiver


class CertificateFileBuilder(FileBuilder):

    @staticmethod
    def build(certificate_pk: int, file_format: CertificateFileFormat) -> bytes:

        try:
            certificate_serializer = CertificateModel.objects.get(pk=certificate_pk).get_certificate_serializer()
        except CertificateModel.DoesNotExist:
            raise ValueError(f'No certificate found for primary key {certificate_pk}.')

        if file_format == CertificateFileFormat.PEM:
            return certificate_serializer.as_pem()
        elif file_format == CertificateFileFormat.DER:
            return certificate_serializer.as_der()
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            return certificate_serializer.as_pkcs7_pem()
        elif file_format == CertificateFileFormat.PKCS7_DER:
            return certificate_serializer.as_pkcs7_der()

        raise ValueError(f'Unsupported file format: {file_format}.')


class CertificateChainFileBuilder(FileBuilder):

    @staticmethod
    def build(credential_pk: int, file_format: CertificateFileFormat) -> bytes:
        pass


class CertificateArchiveFileBuilder(FileBuilder):

    @staticmethod
    def build(certificate_pks: list[int], file_format: CertificateFileFormat, archive_format: ArchiveFormat) -> bytes:

        certificate_models = [
            CertificateModel.objects.get(pk=certificate_pk)
            for certificate_pk in certificate_pks
        ]

        if file_format == CertificateFileFormat.PEM:
            return Archiver.archive(
                data_to_archive = {
                    f'certificate-{index}.pem': certificate.get_certificate_serializer().as_pem()
                    for index, certificate in enumerate(certificate_models)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}.pem': certificate.get_certificate_serializer().as_der()
                    for index, certificate in enumerate(certificate_models)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.PKCS7_PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}.pem': certificate.get_certificate_serializer().as_pkcs7_pem()
                    for index, certificate in enumerate(certificate_models)
                },
                archive_format=archive_format
            )
        elif file_format == CertificateFileFormat.PKCS7_DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}.pem': certificate.get_certificate_serializer().as_pkcs7_der()
                    for index, certificate in enumerate(certificate_models)
                },
                archive_format=archive_format
            )

        raise ValueError(f'Unsupported file format: {file_format}.')





