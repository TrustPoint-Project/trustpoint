from __future__ import annotations
import logging

from django.db import models
from django.utils.translation import gettext_lazy as _

from pki.validator.field import UniqueNameValidator

class IssuedDeviceCertificateModel(models.Model):
    """Issued device certificates model."""

    device = models.ForeignKey(
        'DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.CASCADE,
        related_name='issued_device_certificates')
    issued_device_certificate = models.OneToOneField(
        'pki.CertificateModel',
        verbose_name=_('Issued device certificate'),
        on_delete=models.CASCADE)
    domain = models.ForeignKey('pki.DomainModel', verbose_name=_('Domain'), on_delete=models.CASCADE)


class DeviceModel(models.Model):
    """Device Model."""

    _logger: logging.Logger

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger('tp').getChild(self.__class__.__name__)

    class OnboardingProtocol(models.TextChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 'MA', _('Manual download')
        BROWSER = 'BO', _('Browser download')
        CLI = 'CI', _('Device CLI')
        TP_CLIENT = 'TP', _('Trustpoint Client')
        BRSKI = 'BR', _('BRSKI')
        AOKI = 'AO', _('AOKI')

    class OnboardingStatus(models.TextChoices):
        """Possible onboarding states that a device can be in."""

        NOT_ONBOARDED = 'pending', _('Pending')
        ONBOARDING_RUNNING = 'running', _('Running')
        ONBOARDED = 'onboarded', _('Onboarded')
        ONBOARDING_FAILED = 'failed', _('Failed')
        REVOKED = 'revoked', _('Revoked')

    #   Available related names:
    #       issued_device_certificates : IssuedDeviceCertificateModel

    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default=f'New-Device', validators=[UniqueNameValidator()]
    )
    serial_number = models.CharField(_('Serial-Number'), max_length=100)
    onboarding_status = models.CharField(verbose_name=_('Onboarding Status'),
        max_length=16, choices=OnboardingStatus, default=OnboardingStatus.NOT_ONBOARDED, blank=True
    )
    primary_domain = models.ForeignKey(
        'pki.DomainModel',
        verbose_name=_('Primary Domain'),
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='primary_domain_devices')
    primary_domain_ldevid = models.OneToOneField(
        'pki.CertificateModel',
        verbose_name=_('LDevID Certificate'),
        on_delete=models.SET_NULL,
        blank=True,
        null=True
    )
    secondary_domains = models.ManyToManyField(
        'pki.DomainModel',
        verbose_name=_('Secondary Domains'),
        related_name='secondary_domain_devices')
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self) -> str:
        """Returns a Device object in human-readable format.

        Returns: A formatted string containing the device name and serial number.
        """
        return f'Device({self.unique_name}, {self.serial_number})'
