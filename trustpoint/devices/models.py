from __future__ import annotations

from django.db import models    # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from django.contrib.contenttypes.fields import GenericForeignKey   # type: ignore[import-untyped]
from django.contrib.contenttypes.models import ContentType # type: ignore[import-untyped]
from core.validator.field import UniqueNameValidator


from pki.models import CertificateModel, DomainModel, CredentialModel


class DeviceModel(models.Model):


    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 0, _('Manual download')
        BROWSER = 1, _('Browser download')
        CLI = 2, _('Device CLI')
        TP_CLIENT_PW = 3, _('Trustpoint Client')
        AOKI = 4, _('AOKI')
        BRSKI = 5, _('BRSKI')


    class OnboardingStatus(models.IntegerChoices):
        """Onboarding status."""

        PENDING = 0, _('Pending')
        ONBOARDED = 1, _('Onboarded')


    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default=f'New-Device', validators=[UniqueNameValidator()]
    )
    serial_number = models.CharField(_('Serial-Number'), max_length=100)
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        related_name='devices',
        blank=True,
        null=True,
        on_delete=models.PROTECT
    )

    onboarding_protocol = models.IntegerField(verbose_name=_('Onboarding Protocol'), choices=OnboardingProtocol)
    onboarding_status = models.IntegerField(
        verbose_name=_('Onboarding Status'),
        choices=OnboardingStatus,
        default=OnboardingStatus.PENDING)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)


class IssuedDomainCredentialModel(models.Model):

    issued_domain_credential_certificate = models.OneToOneField(
        CertificateModel,
        verbose_name=_('Issued Domain Credential'),
        on_delete=models.CASCADE,
        related_name='issued_domain_credential')
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.CASCADE,
        related_name='issued_domain_credentials')

    domain_credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)


class IssuedApplicationCertificate(models.Model):

    device = models.ForeignKey(
        DeviceModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    domain_credential = models.ForeignKey(
        IssuedDomainCredentialModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')

    application_certificate = models.ForeignKey(
        CertificateModel,
        verbose_name=_('Application Certificate'),
        on_delete=models.CASCADE)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)