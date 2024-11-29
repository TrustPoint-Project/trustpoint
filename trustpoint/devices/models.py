"""Module that contains all models corresponding to the devices app."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.db.models import Count, QuerySet
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from pki import CertificateStatus, CertificateTypes, ReasonCode
from pki.validator.field import UniqueNameValidator
from taggit.managers import TaggableManager

if TYPE_CHECKING:
    from pki.models import CertificateModel, DomainModel, IssuedDeviceCertificateModel

    from . import OnboardingProtocol

log = logging.getLogger('tp.devices')


class Device(models.Model):
    """Device Model."""

    issued_device_certificates: models.Manager[IssuedDeviceCertificateModel]
    device_name: models.CharField = models.CharField(
        _('Device name'), max_length=100, unique=True, default='test', validators=[UniqueNameValidator()]
    )
    device_serial_number: models.CharField = models.CharField(_('Serial number'), max_length=100, blank=True)

    domains: models.ManyToManyField = models.ManyToManyField(
        'pki.DomainModel',
        verbose_name=_('Domains'),
        related_name='devices',
        blank=True
    )
    created_at: models.DateTimeField = models.DateTimeField(default=timezone.now)
    tags = TaggableManager(blank=True)

    def __str__(self: Device) -> str:
        """Returns a Device object in human-readable format.

        Returns: A formatted string containing the device name.
        """
        return self.device_name

    def get_ldevids_by_domain(self, domain: DomainModel) -> QuerySet | None:
        """Retrieves the current active LDevID certificate for a specified domain.

        Args:
            domain: The domain for which the current active LDevID certificate should be retrieved.

        Returns:
            The active LDevID certificate if found, otherwise None.

        Raises:
            IssuedDeviceCertificateModel.ObjectDoesNotExist: If no active LDevID certificates are found.
        """
        try:
            return self.issued_device_certificates.filter(
                certificate_type=CertificateTypes.LDEVID,
                domain=domain,
                certificate__certificate_status=CertificateStatus.OK,
            )
        except ObjectDoesNotExist:
            return None

    def get_all_active_certs_by_domain(self, domain: DomainModel) -> dict:
        """Retrieves all active certificates for a specified domain, grouped by type.

        Args:
            domain: The domain for which active certificates should be retrieved.

        Returns:
            dict: A dictionary containing:
                - 'domain': The domain for the certificates.
                - 'ldevid': The current active LDevID certificate or None if unavailable.
                - 'other': A queryset of other active certificates excluding LDevID certificates.
        """
        query_sets = self.issued_device_certificates.filter(
            domain=domain, certificate__certificate_status=CertificateStatus.OK
        ).exclude(certificate_type=CertificateTypes.LDEVID)

        return {'domain': domain, 'ldevids': self.get_ldevids_by_domain(domain=domain), 'other': query_sets}

    def save_certificate(
        self,
        certificate: CertificateModel,
        certificate_type: CertificateTypes,
        domain: DomainModel,
        template_name: str,
        onboarding_protocol: str
    ) -> None:
        """Saves a certificate for the device.

        Args:
            certificate (CertificateModel): The certificate to save.
            certificate_type (CertificateTypes): The type of the certificate.
            domain (DomainModel): The associated domain.
            template_name (str): Name of the certificate template.
            onboarding_protocol (str): The onboarding protocol used.
        """
        self.issued_device_certificates.create(
            certificate=certificate,
            certificate_type=certificate_type,
            domain=domain,
            template_name=template_name,
            onboarding_protocol=onboarding_protocol,
        )

    def revoke_ldevid(self: Device, revocation_reason: ReasonCode) -> bool:
        """Revokes the LDevID.

        Args:
            revocation_reason (str): The reason for revocation.

        Returns:
            bool: True if the revocation was successful, False otherwise.
        """
        return True
    #     ldevid = None

    #     ldevid = self.get_current_ldevid_by_domain(domain=self.domains)

    #     if not ldevid:
    #         return False

    #     with transaction.atomic():
    #         revocation_success = ldevid.revoke(revocation_reason)
    #         ldevid = None
    #         if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDED:
    #             if revocation_success:
    #                 self.device_onboarding_status = DeviceOnboardingStatus.REVOKED
    #             else:
    #                 # TODO(Air): Check if this makes sense to express the state "cannot revoke since CA is gone"
    #                 self.device_onboarding_status = DeviceOnboardingStatus.ONBOARDING_FAILED
    #         self.save()

    #     if not revocation_success:
    #         log.error('Failed to revoke LDevID for device %s', self.device_name)
    #         return False
    #     log.info('Revoked LDevID for device %s', self.device_name)
    #     return True

    @classmethod
    def get_by_id(cls: type[Device], device_id: int) -> Device | None:
        """Retrieve a device by its ID.

        Args:
            device_id (int): The ID of the device.

        Returns:
            Device | None: The device if found, otherwise None.
        """
        try:
            return cls.objects.get(pk=device_id)
        except cls.DoesNotExist:
            return None


    @classmethod
    def get_by_name(cls: type[Device], device_name: str) -> Device | None:
        """Retrieve a device by its name.

        Args:
            device_name (str): The name of the device.

        Returns:
            Device | None: The device if found, otherwise None.
        """
        try:
            return cls.objects.get(device_name=device_name)
        except cls.DoesNotExist:
            return None

    def get_domain(self, domain_id: int) -> DomainModel:
        """Retrieve a domain by its ID.

        Args:
            domain_id (int): The ID of the domain.

        Returns:
            DomainModel: The domain associated with the given ID.
        """
        return self.domains.get(pk=domain_id)

    @classmethod
    def check_onboarding_prerequisites(
        cls: type[Device], device_id: int, domain_id: int, allowed_onboarding_protocols: list[OnboardingProtocol]
    ) -> tuple[bool, str | None]:
        """Check if the prerequisites for onboarding are met.

        Args:
            device_id (int): The ID of the device.
            domain_id (int): The ID of the domain.
            allowed_onboarding_protocols (list[OnboardingProtocol]): List of allowed protocols.

        Returns:
            tuple[bool, str | None]: A boolean indicating success and an optional error message.
        """
        device = cls.get_by_id(device_id)

        if not device:
            return False, f'Onboarding: Device with ID {device_id} not found.'

        domain = device.get_domain(domain_id)
        if not domain:
            return False, f'Onboarding: Please select a domain for device {device.device_name} first.'

        if not domain.issuing_ca:
            return False, f'Onboarding: domain {domain.unique_name} has no issuing CA set.'

        # if device.onboarding_protocol not in allowed_onboarding_protocols:
        #     try:
        #         label = OnboardingProtocol(device.onboarding_protocol).label
        #     except ValueError:
        #         return False, 'Onboarding: Please select a valid onboarding protocol.'

        #     return False, f'Onboarding protocol {label} is not implemented.'

        # TODO(Air): check that device is not already onboarded
        # Re-onboarding might be a valid use case, e.g. to renew a certificate
        # if device.device_onboarding_status == DeviceOnboardingStatus.ONBOARDED:
        #     log.warning('Re-onboarding device %s which is already onboarded.', device.device_name)

        return True, None

    def _render_onboarded_revoke(self) -> str:
        """Renders the 'Revoke' onboarding action for devices that have status Onboarded.

        Returns:
            str: The html hyperlink for the details-view.
        """
        return format_html(
            '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
            reverse('onboarding:revoke', kwargs={'device_id': self.pk}),
            _('Revoke Certificate'),
        )

    def _render_running_cancel(self) -> str:
        """Renders the 'Cancel' action for devices that have status Running.

        Returns:
            str: The html hyperlink for the details-view.
        """
        return format_html(
            '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
            reverse('onboarding:exit', kwargs={'device_id': self.pk}),
            _('Cancel Onboarding'),
        )

    def render_onboarding_action(self) -> str:
        """Creates the html hyperlink button for onboarding action.

        Returns:
            str: The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingProtocolError:
                Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately.
        """
        return ''
        # if not self.domains:
        #     return ''
        # is_manual = self.onboarding_protocol == OnboardingProtocol.MANUAL
        # is_cli = self.onboarding_protocol == OnboardingProtocol.CLI
        # is_client = self.onboarding_protocol == OnboardingProtocol.TP_CLIENT
        # is_browser = self.onboarding_protocol == OnboardingProtocol.BROWSER
        # if is_cli or is_client or is_manual or is_browser:
        #     return self._render_manual_onboarding_action()

        # is_brski = self.onboarding_protocol == OnboardingProtocol.BRSKI
        # is_aoki = self.onboarding_protocol == OnboardingProtocol.AOKI
        # if is_brski or is_aoki:
        #     return self._render_zero_touch_onboarding_action()

        # return format_html('<span class="text-danger">' + _('Unknown onboarding protocol!') + '</span>')

    # def _render_zero_touch_onboarding_action(self) -> str:
    #     """Renders the device onboarding section for the zero touch onboarding cases.

    #     Returns:
    #         str: The html hyperlink for the details-view.

    #     Raises:
    #         UnknownOnboardingStatusError:
    #             Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
    #     """
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDED:
    #         # TODO (Air): Revoked devices are free to re-onboard, perhaps also delete IDevID from truststore?
    #         return self._render_onboarded_revoke()
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDING_RUNNING:
    #         return self._render_running_cancel()
    #     if self.device_onboarding_status == DeviceOnboardingStatus.REVOKED:
    #         return format_html(
    #             '<a href="onboarding/reset/{}/" class="btn btn-info tp-onboarding-btn disabled">{}</a>',
    #             self.pk,
    #             _('Onboard again'),
    #         )
    #     if self.device_onboarding_status == DeviceOnboardingStatus.NOT_ONBOARDED:
    #         return format_html(
    #             '<button class="btn btn-success tp-onboarding-btn" disabled>{}</a>', _('Zero-Touch Pending')
    #         )
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDING_FAILED:
    #         return format_html(
    #             '<a href="onboarding/reset/{}/" class="btn btn-warning tp-onboarding-btn disabled">{}</a>',
    #             self.pk,
    #             _('Reset Context'),
    #         )
    #     raise UnknownOnboardingStatusError(self.device_onboarding_status)

    # def _render_manual_onboarding_action(self) -> str:
    #     """Renders the device onboarding button for manual onboarding cases.

    #     Returns:
    #         str:
    #             The html hyperlink for the details-view.

    #     Raises:
    #         UnknownOnboardingStatusError:
    #             Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
    #     """
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDED:
    #         return self._render_onboarded_revoke()
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDING_RUNNING:
    #         return self._render_running_cancel()
    #     if self.device_onboarding_status == DeviceOnboardingStatus.NOT_ONBOARDED:
    #         return format_html(
    #             '<a href="{}" class="btn btn-success tp-onboarding-btn">{}</a>',
    #             reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
    #             _('Start Onboarding'),
    #         )
    #     if self.device_onboarding_status == DeviceOnboardingStatus.ONBOARDING_FAILED:
    #         return format_html(
    #             '<a href="{}" class="btn btn-warning tp-onboarding-btn">{}</a>',
    #             reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
    #             _('Retry Onboarding'),
    #         )
    #     if self.device_onboarding_status == DeviceOnboardingStatus.REVOKED:
    #         return format_html(
    #             '<a href="{}" class="btn btn-info tp-onboarding-btn">{}</a>',
    #             reverse('onboarding:manual-client', kwargs={'device_id': self.pk}),
    #             _('Onboard again'),
    #         )
    #     msg = f'Unknown onboarding status {self.device_onboarding_status}. Failed to render entry in table.'
    #     log.error(msg)
    #     raise UnknownOnboardingStatusError(self.device_onboarding_status)

    @staticmethod
    def count_devices_by_domain_and_status(domain: DomainModel) -> QuerySet:
        """Count devices by their onboarding status for a specific domain.

        Args:
            domain (DomainModel): The domain for which to count devices.

        Returns:
            QuerySet: A queryset with onboarding statuses and counts.
        """
        return (
            Device.objects.filter(domain=domain)
            .values('device_onboarding_status')
            .annotate(count=Count('device_onboarding_status'))
        )
