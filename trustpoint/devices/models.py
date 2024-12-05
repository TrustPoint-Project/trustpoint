from __future__ import annotations

from django.db import models    # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from core.validator.field import UniqueNameValidator


from pki.models import CertificateModel, DomainModel, CredentialModel


class DeviceModel(models.Model):

    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        MANUAL = 1, _('Manual download')
        BROWSER = 2, _('Browser download')
        CLI = 3, _('Device CLI')
        TP_CLIENT_PW = 4, _('Trustpoint Client')
        AOKI = 7, _('AOKI')
        BRSKI = 6, _('BRSKI')

    class OnboardingStatus(models.IntegerChoices):
        """Possible onboarding states that a device can be in."""

        NOT_ONBOARDED = 1, _('Pending')
        ONBOARDING_RUNNING = 2, _('Running')
        ONBOARDED = 3, _('Onboarded')
        ONBOARDING_FAILED = 4, _('Failed')
        REVOKED = 5, _('Revoked')

    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default=f'New-Device', validators=[UniqueNameValidator()]
    )
    serial_number = models.CharField(_('Serial-Number'), max_length=100)
    onboarding_protocol = models.IntegerField(verbose_name=_('Onboarding Protocol'), choices=OnboardingProtocol)
    onboarding_status = models.CharField(
        verbose_name=_('Onboarding Status'),
        max_length=16,
        choices=OnboardingStatus,
        default=OnboardingStatus.NOT_ONBOARDED,
        null=True,
        blank=True
    )


class IssuedDomainCredentialModel(models.Model):

    device = models.ForeignKey(DeviceModel, on_delete=models.CASCADE, related_name='issued_domain_credentials')
    domain = models.ForeignKey(DomainModel, on_delete=models.CASCADE, related_name='issued_domain_credentials')

    domain_credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE)


class IssuedApplicationCertificate(models.Model):

    class ApplicationCertificateTemplateChoice(models.IntegerChoices):

        NONE = 1, _('No Template')
        TLS_CLIENT = 2, _('TLS Client Certificate Template')
        TLS_SERVER = 3, _('TLS Server Certificate Template')
        OPC_UA_CLIENT = 4, _('OPC UA Client Certificate Template')
        OPC_UA_SERVER = 5, _('OPC UA Server Certificate Template')

    device = models.ForeignKey(
        DeviceModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')
    domain_credential = models.ForeignKey(
        IssuedDomainCredentialModel,
        on_delete=models.CASCADE,
        related_name='issued_application_certificates')

    application_certificate = models.ForeignKey(CertificateModel, on_delete=models.CASCADE)
    application_certificate_template = models.PositiveIntegerField(
        _('Certificate Template'),
        choices=ApplicationCertificateTemplateChoice,
        blank=False,
        null=False
    )
