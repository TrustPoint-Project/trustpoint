from django.core.management import BaseCommand
from pathlib import Path
from pki.models import IssuingCa
from util.x509.credentials import CredentialUploadHandler
from django.core.files.uploadedfile import InMemoryUploadedFile
import sys
import io


P12_PATH = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/x509/')
P12_FILE_NAMES = ['rsa-long.p12', 'secp256r1-long.p12', 'secp384r1-long.p12']


class Command(BaseCommand):
    help = 'Fills the Issuing CA DB with test data.'

    def _add_all(self, start_index: int = 1) -> int:
        for j, file_name in enumerate(P12_FILE_NAMES):
            k = j + start_index
            self._add_issuing_ca(P12_PATH / file_name, f'My Issuing CA {k}', b'testing321')
        return start_index + 3

    def _add_issuing_ca(self, p12_path: Path | str, unique_name: str, p12_password: bytes) -> None:
        with open(p12_path, 'rb') as f:
            p12 = f.read()

        normalized_p12 = CredentialUploadHandler.parse_and_normalize_p12(p12, p12_password)

        p12_bytes_io = io.BytesIO(normalized_p12.public_bytes)
        p12_memory_uploaded_file = InMemoryUploadedFile(
            p12_bytes_io, 'p12', f'{unique_name}.p12', 'application/x-pkcs12', sys.getsizeof(p12_bytes_io), None
        )

        issuing_ca = IssuingCa(
            unique_name=unique_name,
            common_name=normalized_p12.common_name,
            root_common_name=normalized_p12.root_common_name,
            not_valid_before=normalized_p12.not_valid_before,
            not_valid_after=normalized_p12.not_valid_after,
            key_type=normalized_p12.key_type,
            key_size=normalized_p12.key_size,
            curve=normalized_p12.curve,
            localization=normalized_p12.localization,
            config_type=normalized_p12.config_type,
            p12=p12_memory_uploaded_file
        )

        # TODO: check if this is kind of atomic or could result in issues
        issuing_ca.save()

    def handle(self, *args, **kwargs):
        i = 1
        for _ in range(0, 5):
            i = self._add_all(i)
