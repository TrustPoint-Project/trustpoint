import tarfile
import zipfile
from io import BytesIO

import pytest
from core.file_builder.archiver import Archiver
from core.file_builder.enum import ArchiveFormat

# Test data
SAMPLE_DATA = {
    'certificate-1.pem': b'-----BEGIN CERTIFICATE-----\nMIIBIjAN...',
    'certificate-2.pem': b'-----BEGIN CERTIFICATE-----\nMIICDjCCAX...',
}
EXPECTED_FILES = ['certificate-1.pem', 'certificate-2.pem']

@pytest.mark.parametrize('archive_format', [ArchiveFormat.ZIP, ArchiveFormat.TAR_GZ])
def test_archiver_creates_non_empty_archive(archive_format):
    """Tests if the Archiver creates a non-empty archive."""
    archive_bytes = Archiver.archive(data_to_archive=SAMPLE_DATA, archive_format=archive_format)

    assert archive_bytes is not None, 'The archive should not be None.'
    assert len(archive_bytes) > 0, 'The archive should not be empty.'

@pytest.mark.parametrize('archive_format', [ArchiveFormat.ZIP, ArchiveFormat.TAR_GZ])
def test_archiver_contains_expected_files(archive_format):
    """Tests if the created archive contains the expected files."""
    archive_bytes = Archiver.archive(data_to_archive=SAMPLE_DATA, archive_format=archive_format)

    if archive_format == ArchiveFormat.ZIP:
        with zipfile.ZipFile(BytesIO(archive_bytes), 'r') as zf:
            actual_files = zf.namelist()
    elif archive_format == ArchiveFormat.TAR_GZ:
        with tarfile.open(fileobj=BytesIO(archive_bytes), mode='r:gz') as tf:
            actual_files = [member.name for member in tf.getmembers()]

    for expected_file in EXPECTED_FILES:
        assert expected_file in actual_files, f'Missing file: {expected_file}'

@pytest.mark.parametrize('archive_format', [ArchiveFormat.ZIP, ArchiveFormat.TAR_GZ])
def test_archiver_archive_integrity(archive_format, tmp_path):
    """Tests if the archive can be extracted without errors."""
    archive_bytes = Archiver.archive(data_to_archive=SAMPLE_DATA, archive_format=archive_format)

    output_dir = tmp_path / 'extracted'
    output_dir.mkdir()

    if archive_format == ArchiveFormat.ZIP:
        with zipfile.ZipFile(BytesIO(archive_bytes), 'r') as zf:
            zf.extractall(output_dir)
    elif archive_format == ArchiveFormat.TAR_GZ:
        with tarfile.open(fileobj=BytesIO(archive_bytes), mode='r:gz') as tf:
            tf.extractall(output_dir, filter='data')

    # Ensure extracted files match expected content
    for file_name, expected_content in SAMPLE_DATA.items():
        extracted_file = output_dir / file_name
        assert extracted_file.exists(), f'File {file_name} was not extracted.'
        assert extracted_file.read_bytes() == expected_content, f'Content mismatch for file {file_name}.'
