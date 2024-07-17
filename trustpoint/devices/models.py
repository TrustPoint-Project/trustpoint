"""Module that contains all models corresponding to the devices app."""


from __future__ import annotations
import logging

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from pki.models import Certificate, DomainProfile, RevokedCertificate

from .exceptions import UnknownOnboardingStatusError

log = logging.getLogger('tp.devices')

class Device(models.Model):
    """Device Model."""

    class DeviceOnboardingStatus(models.TextChoices):
        """Device Onboarding Status."""

        NOT_ONBOARDED = 'P', _('Pending')
        ONBOARDING_RUNNING = 'R', _('Running')
        ONBOARDED = 'O', _('Onboarded')
        ONBOARDING_FAILED = 'F', _('Failed')
        REVOKED = 'D', _('Revoked')

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
            if choice == cls.REVOKED.value:
                return 'info'
            if choice == cls.ONBOARDING_FAILED.value:
                return 'danger'
            raise UnknownOnboardingStatusError(choice)

    class OnboardingProtocol(models.TextChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 'MA', _('Manual download')
        CLI = 'CI', _('Device CLI')
        TP_CLIENT = 'TP', _('Trustpoint Client')
        BRSKI = 'BR', _('BRSKI')
        FIDO = 'FI', _('FIDO FDO')

    device_name = models.CharField(max_length=100, unique=True, default='test')
    device_serial_number = models.CharField(max_length=100, blank=True)
    ldevid = models.ForeignKey(Certificate, on_delete=models.SET_NULL, blank=True, null=True)
    onboarding_protocol = models.CharField(
        max_length=2, choices=OnboardingProtocol, default=OnboardingProtocol.MANUAL, blank=True
    )
    device_onboarding_status = models.CharField(
        max_length=1, choices=DeviceOnboardingStatus, default=DeviceOnboardingStatus.NOT_ONBOARDED, blank=True
    )
    domain_profile = models.ForeignKey(DomainProfile, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self: Device) -> str:
        """Returns a Device object in human-readable format."""
        return f'Device({self.device_name}, {self.device_serial_number})'

    def revoke_ldevid(self: Device) -> bool:
        """Revokes the LDevID.

        Deletes the LDevID file and sets the device status to REVOKED.
        Actual revocation (CRL, OCSP) is not yet implemented.
        """
        if not self.ldevid:
            return False

        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            self.device_onboarding_status = Device.DeviceOnboardingStatus.REVOKED

        RevokedCertificate.objects.create(
                device_name=self.device_name,
                device_serial_number=self.device_serial_number,
                cert_serial_number=self.ldevid.serial_number,
                revocation_datetime=timezone.now(),
                revocation_reason='Requested by user',
                issuing_ca=self.domain_profile.issuing_ca,
                domain_profile=self.domain_profile
            )

        self.ldevid.revoke()
        self.ldevid = None
        self.save()

        # generate CRLs
        self.domain_profile.generate_crl()
        self.domain_profile.issuing_ca.generate_crl()

        log.info('Revoked LDevID for device %s', self.device_name)
        return True

    @classmethod
    def get_by_id(cls: Device, device_id: int) -> Device | None:
        """Returns the device with a given ID."""
        try:
            return cls.objects.get(pk=device_id)
        except cls.DoesNotExist:
            return None

    @classmethod
    def check_onboarding_prerequisites(
            cls: Device, device_id: int,
            allowed_onboarding_protocols: list[Device.OnboardingProtocol]) -> tuple[bool, str | None]:
        """Checks if criteria for starting the onboarding process are met."""
        device = cls.get_by_id(device_id)

        if not device:
            return False, f'Onboarding: Device with ID {device_id} not found.'

        if not device.domain_profile:
            return False, f'Onboarding: Please select an domain profile for device {device.device_name} first.'

        if not device.domain_profile.issuing_ca:
            return False, f'Onboarding: domain profile {device.domain_profile.unique_name} has no issuing CA set.'

        if device.onboarding_protocol not in allowed_onboarding_protocols:
            try:
                label = Device.OnboardingProtocol(device.onboarding_protocol).label
            except ValueError:
                return False, _('Onboarding: Please select a valid onboarding protocol.')

            return False, f'Onboarding protocol {label} is not implemented.'

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate
        if device.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            log.warning('Re-onboarding device %s which is already onboarded.', device.device_name)

        return True, None
