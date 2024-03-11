"""Django management command for adding issuing CA test data."""


from __future__ import annotations

import io
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from devices.models import Device
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.management import BaseCommand
from pki.models import EndpointProfile, IssuingCa
from util.x509.credentials import CredentialUploadHandler

if TYPE_CHECKING:
    from typing import Any


P12_PATH = Path(__file__).parent.parent.parent.parent.parent / Path('tests/data/x509/')
P12_FILE_NAMES = ['rsa-long.p12', 'secp256r1-long.p12', 'secp384r1-long.p12']


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Fills the Issuing CA DB with test data.'

    @staticmethod
    def _add_devices() -> None:
        """Adds the demo devices to the db.

        Returns:
            None
        """
        default_endpoint_profile = EndpointProfile.objects.filter(unique_endpoint='default').first()
        sensors_endpoint_profile = EndpointProfile.objects.filter(unique_endpoint='sensors').first()
        plc_endpoint_profile = EndpointProfile.objects.filter(unique_endpoint='plc').first()
        for i, protocol in enumerate(Device.OnboardingProtocol):
            if i == 0:
                endpoint_profile = default_endpoint_profile
            elif i == 1:
                endpoint_profile = sensors_endpoint_profile
            else:
                endpoint_profile = plc_endpoint_profile
            for j, status in enumerate(Device.DeviceOnboardingStatus):
                serial_number = str(uuid.uuid4()) if status == Device.DeviceOnboardingStatus.ONBOARDED else ''
                dev = Device(
                    device_name=f'Device {protocol[0]}{j + 1}',
                    serial_number=serial_number,
                    endpoint_profile=endpoint_profile,
                    onboarding_protocol=protocol,
                    device_onboarding_status=status,
                )
                dev.save()

    def _add_issuing_cas(self) -> None:
        for i, file_name in enumerate(P12_FILE_NAMES):
            self._add_issuing_ca(
                P12_PATH / file_name, f'My Issuing CA {i+1}', b'testing321', IssuingCa.ConfigType.F_P12
            )
        for i, file_name in enumerate(P12_FILE_NAMES):
            self._add_issuing_ca(
                P12_PATH / file_name,
                f'My Issuing CA {i+len(P12_FILE_NAMES)+1}',
                b'testing321',
                IssuingCa.ConfigType.F_PEM,
            )

    @staticmethod
    def _add_issuing_ca(
        p12_path: Path | str, unique_name: str, p12_password: bytes, config_type: IssuingCa.ConfigType
    ) -> None:
        with Path(p12_path).open('rb') as p12_file:
            p12 = p12_file.read()

        normalized_p12 = CredentialUploadHandler.parse_and_normalize_p12(p12, p12_password)

        # noinspection DuplicatedCode
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
            config_type=config_type.value,
            p12=p12_memory_uploaded_file,
        )

        issuing_ca.save()

    @staticmethod
    def _add_endpoint_profiles() -> None:
        issuing_cas = IssuingCa.objects.all()
        EndpointProfile(unique_endpoint='default', issuing_ca=issuing_cas[0]).save()
        EndpointProfile(unique_endpoint='sensors', issuing_ca=issuing_cas[1]).save()
        EndpointProfile(unique_endpoint='plc', issuing_ca=issuing_cas[2]).save()

    def handle(self, *_args: Any, **_kwargs: Any) -> None:
        """Main entry point for the command."""
        self._add_issuing_cas()
        self._add_endpoint_profiles()
        self._add_devices()
