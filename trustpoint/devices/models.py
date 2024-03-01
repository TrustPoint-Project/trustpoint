from __future__ import annotations


from django.db import models
from django.utils import timezone
from pki.models import EndpointProfile
from django.utils.translation import gettext_lazy as _


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
            if isinstance(choice, str):
                choice = Device.DeviceOnboardingStatus(choice)
            if choice == cls.NOT_ONBOARDED or choice == cls.ONBOARDING_RUNNING:
                return 'warning'
            if choice == cls.ONBOARDED:
                return 'success'
            if choice == cls.ONBOARDED:
                return 'danger'
            raise ValueError('Unknown device onboarding status.')

    class OnboardingProtocol(models.TextChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 'MA', _('Manual (CLI)')
        CLIENT = 'CL', _('Trustpoint Client')
        BRSKI = 'BR', _('BRSKI')
        FIDO = 'FI', _('FIDO FDO')

    device_name = models.CharField(max_length=100, unique=True)
    serial_number = models.CharField(max_length=100, blank=True)
    ldevid = models.FileField(blank=True, null=True)
    onboarding_protocol = models.CharField(
        max_length=2,
        choices=OnboardingProtocol,
        default=OnboardingProtocol.MANUAL,
        blank=True)
    device_onboarding_status = models.CharField(
        max_length=1,
        choices=DeviceOnboardingStatus,
        default=DeviceOnboardingStatus.NOT_ONBOARDED,
        blank=True)
    endpoint_profile = models.ForeignKey(EndpointProfile, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self: Device) -> str:
        """Returns a Device object in human-readable format."""
        return f'Device({self.device_name}, {self.serial_number})'
    
    @classmethod
    def get_by_id(cls, device_id: int) -> Device | None:
        """Returns the device with a given ID."""
        try:
            return cls.objects.get(pk=device_id)
        except cls.DoesNotExist:
            return None
