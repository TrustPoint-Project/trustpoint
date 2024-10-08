"""Module that contains all models corresponding to the devices app."""


from __future__ import annotations

import logging
import re

from django.db import models
from django.db.models import Count
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from pki.models import CertificateModel, DomainModel, RevokedCertificate
from taggit.managers import TaggableManager

from .exceptions import UnknownOnboardingStatusError

from pki.validator.field import UniqueNameValidator, UniqueNameLowerCaseValidator

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
        BROWSER = 'BO', _('Browser download')
        CLI = 'CI', _('Device CLI')
        TP_CLIENT = 'TP', _('Trustpoint Client')
        BRSKI = 'BR', _('BRSKI')
        AOKI = 'AO', _('AOKI')

    device_name = models.CharField(max_length=100, unique=True, default='test', validators=[UniqueNameValidator()])
    device_serial_number = models.CharField(max_length=100, blank=True)
    ldevid = models.ForeignKey(CertificateModel, on_delete=models.SET_NULL, blank=True, null=True)
    onboarding_protocol = models.CharField(
        max_length=2, choices=OnboardingProtocol, default=OnboardingProtocol.MANUAL, blank=True
    )
    device_onboarding_status = models.CharField(
        max_length=1, choices=DeviceOnboardingStatus, default=DeviceOnboardingStatus.NOT_ONBOARDED, blank=True
    )
    domain = models.ForeignKey(DomainModel, on_delete=models.SET_NULL, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    tags = TaggableManager(blank=True)

    def __str__(self: Device) -> str:
        """Returns a Device object in human-readable format."""
        return f'Device({self.device_name}, {self.device_serial_number})'

    def revoke_ldevid(self: Device, revocation_reason) -> bool:
        """Revokes the LDevID.

        Deletes the LDevID file and sets the device status to REVOKED.
        Actual revocation (CRL, OCSP) is not yet implemented.
        """
        if not self.ldevid:
            return False

        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            self.device_onboarding_status = Device.DeviceOnboardingStatus.REVOKED

        self.ldevid.revoke(revocation_reason)
        self.ldevid = None
        self.save()

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

        if not device.domain:
            return False, f'Onboarding: Please select a domain for device {device.device_name} first.'

        if not device.domain.issuing_ca:
            return False, f'Onboarding: domain {device.domain.unique_name} has no issuing CA set.'

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

    def _render_onboarded_revoke(self) -> str:
        """Renders the 'Revoke' onboarding action for devices that have status Onboarded.

        Returns:
            str: The html hyperlink for the details-view.
        """
        return format_html(
            '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
            reverse('onboarding:revoke', kwargs={'device_id': self.pk}),
            _('Revoke Certificate')
        )
    
    def _render_running_cancel(self) -> str:
        """Renders the 'Cancel' action for devices that have status Running.

        Returns:
            str: The html hyperlink for the details-view.
        """
        return format_html(
            '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
            reverse('onboarding:exit', kwargs={'device_id': self.pk}),
            _('Cancel Onboarding')
        )

    def render_onboarding_action(self) -> str:
        """Creates the html hyperlink button for onboarding action.

        Returns:
            str: The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingProtocolError:
                Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately.
        """
        if not self.domain:
            return ''
        is_manual = self.onboarding_protocol == Device.OnboardingProtocol.MANUAL
        is_cli = self.onboarding_protocol == Device.OnboardingProtocol.CLI
        is_client = self.onboarding_protocol == Device.OnboardingProtocol.TP_CLIENT
        is_browser = self.onboarding_protocol == Device.OnboardingProtocol.BROWSER
        if is_cli or is_client or is_manual or is_browser:
            return self._render_manual_onboarding_action()

        is_brski = self.onboarding_protocol == Device.OnboardingProtocol.BRSKI
        is_aoki = self.onboarding_protocol == Device.OnboardingProtocol.AOKI
        if is_brski or is_aoki:
            return self._render_zero_touch_onboarding_action()

        return format_html('<span class="text-danger">' + _('Unknown onboarding protocol!') + '</span>')

    def _render_zero_touch_onboarding_action(self) -> str:
        """Renders the device onboarding section for the zero touch onboarding cases.

        Returns:
            str: The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingStatusError:
                Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
        """
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            # TODO (Air): Revoked devices are free to re-onboard, perhaps also delete IDevID from truststore?
            return self._render_onboarded_revoke()
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return self._render_running_cancel()
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.REVOKED:
            return format_html(
                '<a href="onboarding/reset/{}/" class="btn btn-info tp-onboarding-btn disabled">{}</a>',
                self.pk, _('Onboard again')
            )
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.NOT_ONBOARDED:
            return format_html(
                '<button class="btn btn-success tp-onboarding-btn" disabled>{}</a>',
                _('Zero-Touch Pending')
            )
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="onboarding/reset/{}/" class="btn btn-warning tp-onboarding-btn disabled">{}</a>',
                self.pk, _('Reset Context')
            )
        raise UnknownOnboardingStatusError(self.device_onboarding_status)

    def _render_manual_onboarding_action(self) -> str:
        """Renders the device onboarding button for manual onboarding cases.

        Returns:
            str:
                The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingStatusError:
                Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
        """
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            return self._render_onboarded_revoke()
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return self._render_running_cancel()
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.NOT_ONBOARDED:
            return format_html(
                '<a href="{}" class="btn btn-success tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
                _('Start Onboarding')
            )
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="{}" class="btn btn-warning tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
                _('Retry Onboarding')
            )
        if self.device_onboarding_status == Device.DeviceOnboardingStatus.REVOKED:
            return format_html(
                '<a href="{}" class="btn btn-info tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
                _('Onboard again')
            )
        log.error(f'Unknown onboarding status {self.device_onboarding_status}. Failed to render entry in table.')
        raise UnknownOnboardingStatusError(self.device_onboarding_status)

    @staticmethod
    def count_devices_by_domain_and_status(domain: DomainModel) -> int:
        """Returns the number of devices for a given domain, grouped by onboarding status."""
        return Device.objects.filter(domain=domain) \
            .values('device_onboarding_status') \
            .annotate(count=Count('device_onboarding_status'))
