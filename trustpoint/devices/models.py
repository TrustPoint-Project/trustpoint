from __future__ import annotations


from django.db import models
from django.utils import timezone
from pki.models import EndpointProfile
from django.utils.translation import gettext_lazy as _


class Device(models.Model):
    """Device Model."""

    class DeviceOnboardingStatus(models.TextChoices):
        """Device Onboarding Status."""

        NOT_ONBOARDED = 'NO', _('Not onboarded')
        ONBOARDING_RUNNING = 'OR', _('Onboarding running')
        ONBOARDED = 'OD', _('Onboarded')
        ONBOARDING_FAILED = 'OF', _('Onboarding failed')

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
        max_length=2,
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
