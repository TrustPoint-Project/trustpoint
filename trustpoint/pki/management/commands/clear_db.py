from __future__ import annotations


from django.core.management import BaseCommand
from devices.models import Device
from pki.models import IssuingCa, EndpointProfile
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import Any


class Command(BaseCommand):
    """Django management command for adding issuing CA test data."""

    help = 'Clears all DB entries.'

    def handle(self, *_args: Any, **_kwargs: Any) -> None:
        """Main entry point for the command."""
        Device.objects.all().delete()
        IssuingCa.objects.all().delete()
        EndpointProfile.objects.all().delete()
