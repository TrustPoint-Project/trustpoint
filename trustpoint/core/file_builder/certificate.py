"""Module that contains certificate file builder."""

from __future__ import annotations

from core.file_builder.archiver import Archiver
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat
from core.serializer import CertificateCollectionSerializer, CertificateSerializer


class CertificateFileBuilder:
    """Builds a single certificate file."""

    @staticmethod
    def build(certificate_serializer: CertificateSerializer, file_format: CertificateFileFormat) -> bytes:
        """Builds a single certificate file.

        Args:
            certificate_serializer: The certificate serializer holding the certificate to use.
            file_format: The desired file format.

        Returns:
            The bytes to be stored on disk.
        """
        if file_format == CertificateFileFormat.PEM:
            return certificate_serializer.as_pem()
        if file_format == CertificateFileFormat.DER:
            return certificate_serializer.as_der()
        if file_format == CertificateFileFormat.PKCS7_PEM:
            return certificate_serializer.as_pkcs7_pem()
        if file_format == CertificateFileFormat.PKCS7_DER:
            return certificate_serializer.as_pkcs7_der()

        err_msg = f'Unsupported file format: {file_format}.'
        raise ValueError(err_msg)


class CertificateCollectionBuilder:
    """Builds files containing multiple certificates."""

    @staticmethod
    def build(
            certificate_collection_serializer: CertificateCollectionSerializer,
            file_format: CertificateFileFormat) -> bytes:
        """Builds a file containing multiple certificates.

        Args:
            certificate_collection_serializer: The certificate collection serializer holding the certificate to use.
            file_format: The desired file format.

        Returns:
            The bytes to be stored on disk.
        """

        if file_format == CertificateFileFormat.PEM:
            return certificate_collection_serializer.as_pem()
        if file_format == CertificateFileFormat.PKCS7_PEM:
            return certificate_collection_serializer.as_pkcs7_pem()
        if file_format == CertificateFileFormat.PKCS7_DER:
            return certificate_collection_serializer.as_pkcs7_der()

        err_msg = f'Unsupported file format: {file_format}.'
        raise ValueError(err_msg)


class CertificateArchiveFileBuilder:
    """Builds an archive containing single certificates as files."""

    @staticmethod
    def build(
        certificate_serializers: CertificateCollectionSerializer | list[CertificateSerializer],
        file_format: CertificateFileFormat,
        archive_format: ArchiveFormat,
    ) -> bytes:
        """Builds an archive containing single certificates as files.

        Args:
            certificate_serializers:  The certificate serializers holding the certificates to use.
            file_format: The desired file format.
            archive_format: The desired archive format.

        Returns:
            bytes: The archive in byte representation.
        """
        if isinstance(certificate_serializers, CertificateCollectionSerializer):
            certificate_serializers = certificate_serializers.as_certificate_serializer_list()

        if file_format == CertificateFileFormat.PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pem()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format,
            )
        if file_format == CertificateFileFormat.DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_der()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format,
            )
        if file_format == CertificateFileFormat.PKCS7_PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pkcs7_pem()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format,
            )
        if file_format == CertificateFileFormat.PKCS7_DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate.as_pkcs7_der()
                    for index, certificate in enumerate(certificate_serializers)
                },
                archive_format=archive_format,
            )

        err_msg = f'Unsupported file format: {file_format}.'
        raise ValueError(err_msg)


class CertificateCollectionArchiveFileBuilder:
    """Builds an archive containing multiple certificates as files."""

    @staticmethod
    def build(
        certificate_collection_serializers: list[CertificateCollectionSerializer],
        file_format: CertificateFileFormat,
        archive_format: ArchiveFormat,
    ) -> bytes:
        """Builds an archive containing single certificates as files.

        Args:
            certificate_collection_serializers:  The certificate collection serializers holding the certificates to use.
            file_format: The desired file format.
            archive_format: The desired archive format.

        Returns:
            bytes: The archive in byte representation.
        """

        if file_format == CertificateFileFormat.PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate_collection.as_pem()
                    for index, certificate_collection in enumerate(certificate_collection_serializers)
                },
                archive_format=archive_format,
            )
        if file_format == CertificateFileFormat.PKCS7_PEM:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate_collection.as_pkcs7_pem()
                    for index, certificate_collection in enumerate(certificate_collection_serializers)
                },
                archive_format=archive_format,
            )
        if file_format == CertificateFileFormat.PKCS7_DER:
            return Archiver.archive(
                data_to_archive={
                    f'certificate-{index}{file_format.file_extension}': certificate_collection.as_pkcs7_der()
                    for index, certificate_collection in enumerate(certificate_collection_serializers)
                },
                archive_format=archive_format,
            )

        err_msg = f'Unsupported file format: {file_format}.'
        raise ValueError(err_msg)
