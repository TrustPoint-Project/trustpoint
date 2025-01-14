from itertools import product

import pytest
from core.file_builder.certificate import CertificateArchiveFileBuilder, CertificateFileBuilder
from core.file_builder.enum import ArchiveFormat, CertificateFileFormat

CERTIFICATE_FORMATS = [
    CertificateFileFormat.PEM,
    CertificateFileFormat.DER,
    CertificateFileFormat.PKCS7_PEM,
    CertificateFileFormat.PKCS7_DER,
]

ARCHIVE_FORMATS = [
    ArchiveFormat.ZIP,
    ArchiveFormat.TAR_GZ,
]

@pytest.mark.parametrize("file_format", CERTIFICATE_FORMATS)
def test_certificate_file_builder(mock_certificate_serializer, file_format) -> None:
    """Tests whether CertificateFileBuilder returns the expected byte content for various file formats."""
    result = CertificateFileBuilder.build(mock_certificate_serializer, file_format)
    assert isinstance(result, bytes)
    assert len(result) > 0


@pytest.mark.parametrize("file_format, archive_format", product(CERTIFICATE_FORMATS, ARCHIVE_FORMATS))
def test_certificate_archive_file_builder(mock_certificate_collection_serializer, file_format, archive_format):
    """Tests building an archive with all combinations of certificate file formats and archive formats."""
    archive = CertificateArchiveFileBuilder.build(
        mock_certificate_collection_serializer,
        file_format,
        archive_format
    )
    assert isinstance(archive, bytes)
    assert len(archive) > 0
