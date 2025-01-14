from core.file_builder.enum import ArchiveFormat, CertificateFileFormat


def test_archive_format_zip():
    assert ArchiveFormat.ZIP.value == "zip"
    assert ArchiveFormat.ZIP.mime_type == "application/zip"
    assert ArchiveFormat.ZIP.file_extension == ".zip"

def test_archive_format_targz():
    assert ArchiveFormat.TAR_GZ.value == "tar_gz"
    assert ArchiveFormat.TAR_GZ.mime_type == "application/gzip"
    assert ArchiveFormat.TAR_GZ.file_extension == ".tar.gz"

def test_certificate_file_format_pem():
    assert CertificateFileFormat.PEM.value == "pem"
    assert CertificateFileFormat.PEM.mime_type == "application/x-pem-file"
    assert CertificateFileFormat.PEM.file_extension == ".pem"

def test_certificate_file_format_der():
    assert CertificateFileFormat.DER.value == "der"
    assert CertificateFileFormat.DER.mime_type == "application/pkix-cert"
    assert CertificateFileFormat.DER.file_extension == ".cer"
