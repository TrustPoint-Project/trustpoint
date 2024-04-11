"""Module that contains all models corresponding to the devices app."""


from __future__ import annotations

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from pki.models import EndpointProfile

from .exceptions import UnknownOnboardingStatusError


class Device(models.Model):
    """Device Model."""

    class DeviceOnboardingStatus(models.TextChoices):
        """Device Onboarding Status."""

        NOT_ONBOARDED = 'P', _('Pending')
        ONBOARDING_RUNNING = 'R', _('Running')
        ONBOARDED = 'O', _('OK')
        ONBOARDING_FAILED = 'F', _('Failed')

        @classmethod
        def get_color(cls: Device.DeviceOnboardingStatus, choice: Device.DeviceOnboardingStatus | str) -> str:
            """Gets the bootstrap 5.3 color name."""
            choice = str(choice)
            if choice == cls.ONBOARDING_RUNNING:
                return 'warning-emphasis'
            if choice == cls.NOT_ONBOARDED.value:
                return 'warning'
            if choice == cls.ONBOARDED.value:
                return 'success'
            if choice == cls.ONBOARDING_FAILED.value:
                return 'danger'
            raise UnknownOnboardingStatusError

    class OnboardingProtocol(models.TextChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 'MA', _('Manual download')
        CLI = 'CI', _('Device CLI')
        TP_CLIENT = 'TP', _('Trustpoint Client')
        BRSKI = 'BR', _('BRSKI')
        FIDO = 'FI', _('FIDO FDO')

    device_name = models.CharField(max_length=100, unique=True, default='test')
    serial_number = models.CharField(max_length=100, blank=True)
    ldevid = models.FileField(blank=True, null=True)
    onboarding_protocol = models.CharField(
        max_length=2, choices=OnboardingProtocol, default=OnboardingProtocol.MANUAL, blank=True
    )
    device_onboarding_status = models.CharField(
        max_length=1, choices=DeviceOnboardingStatus, default=DeviceOnboardingStatus.NOT_ONBOARDED, blank=True
    )
    endpoint_profile = models.ForeignKey(EndpointProfile, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self: Device) -> str:
        """Returns a Device object in human-readable format."""
        return f'Device({self.device_name}, {self.serial_number})'

    def revoke_ldevid(self: Device) -> bool:
        """Revokes the LDevID.

        Deletes the LDevID file and sets the device status to NOT_ONBOARDED.
        Actual revocation (CRL, OCSP) is not yet implemented.
        """
        if not self.ldevid:
            return False

        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            # TODO(Air): Perhaps extra status for revoked devices?
            self.device_onboarding_status = Device.DeviceOnboardingStatus.NOT_ONBOARDED
        self.ldevid.delete()
        self.ldevid = None
        self.save()
        return True

    @classmethod
    def get_by_id(cls: Device, device_id: int) -> Device | None:
        """Returns the device with a given ID."""
        try:
            return cls.objects.get(pk=device_id)
        except cls.DoesNotExist:
            return None

    @classmethod
    def check_onboarding_prerequisites(cls: Device, device_id: int,
                                       allowed_onboarding_protocols: list[Device.OnboardingProtocol]
                                        ) -> tuple[bool, str | None]:
        """Checks if criteria for starting the onboarding process are met."""
        device = cls.get_by_id(device_id)

        if not device:
            return (False, f'Onboarding: Device with ID {device_id} not found.')

        if not device.endpoint_profile:
            return (False, f'Onboarding: Please select an endpoint profile for device {device.device_name} first.')

        if not device.endpoint_profile.issuing_ca:
            return (False, f'Onboarding: Endpoint profile {device.endpoint_profile.unique_name} has no issuing CA set.')

        if device.onboarding_protocol not in allowed_onboarding_protocols:
            try:
                label = Device.OnboardingProtocol(device.onboarding_protocol).label
            except ValueError:
                return (False, 'Onboarding: Please select a valid onboarding protocol.')

            return (False, f'Onboarding protocol {label} is not implemented.')

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate

        return (True, None)
