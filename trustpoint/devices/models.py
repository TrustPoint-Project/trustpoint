from __future__ import annotations

from typing import Any

from django.db import models
from django.db.models import UniqueConstraint
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.models import ContentType
from core.validator.field import UniqueNameValidator
from django.core.exceptions import ValidationError

from pki.models import CertificateModel, DomainModel, CredentialModel, IssuingCaModel

from pki.models.credential import CredentialModel


class DeviceModel(models.Model):

    objects: models.Manager['DeviceModel']

    def __str__(self) -> str:
        return f'DeviceModel(unique_name={self.unique_name})'


    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        NO_ONBOARDING = 0, _('No Onboarding')
        MANUAL = 1, _('Manual download')
        BROWSER = 2, _('Browser download')
        CLI = 3, _('Device CLI')
        TP_CLIENT_PW = 4, _('Trustpoint Client')
        AOKI = 5, _('AOKI')
        BRSKI = 6, _('BRSKI')


    class OnboardingStatus(models.IntegerChoices):
        """Onboarding status."""

        NO_ONBOARDING = 0, _('No Onboarding')
        PENDING = 1, _('Pending')
        ONBOARDED = 2, _('Onboarded')

    id = models.AutoField(primary_key=True)
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

    onboarding_protocol = models.IntegerField(
        verbose_name=_('Onboarding Protocol'),
        choices=OnboardingProtocol,
        null=False,
        blank=False)
    onboarding_status = models.IntegerField(
        verbose_name=_('Onboarding Status'),
        choices=OnboardingStatus,
        blank=False,
        null=False)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)


class IssuedCredentialModel(models.Model):
    """Model for all credentials and certificates that have been issued or requested by the Trustpoint."""

    objects: models.Manager['IssuedCredentialModel']

    class Meta:
        constraints = [
            UniqueConstraint(fields=['device', 'common_name'], name='unique_common_names_for_each_device')
        ]

    class IssuedCredentialType(models.IntegerChoices):
        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        APPLICATION_CREDENTIAL = 1, _('Application Credential')

    class IssuedCredentialPurpose(models.IntegerChoices):
        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        GENERIC = 1, _('Generic')
        TLS_CLIENT = 2, _('TLS-Client')
        TLS_SERVER = 3, _('TLS-Server')

    id = models.AutoField(primary_key=True)

    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    issued_credential_type = models.IntegerField(
        choices=IssuedCredentialType,
        verbose_name=_('Credential Type'))
    issued_credential_purpose = models.IntegerField(
        choices=IssuedCredentialPurpose,
        verbose_name=_('Credential Purpose'))
    credential = models.OneToOneField(
        CredentialModel,
        verbose_name=_('Credential'),
        on_delete=models.PROTECT,
        related_name='issued_credential',
        null=False,
        blank=False
    )
    device = models.ForeignKey(
        DeviceModel,
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='issued_credentials'
    )
    domain = models.ForeignKey(
        DomainModel,
        verbose_name=_('Domain'),
        on_delete=models.PROTECT,
        related_name='issued_credentials'
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __str__(self) -> str:
        return f'IssuedCredentialModel()'

    def clean(self) -> None:
        if IssuedCredentialModel.objects.filter(common_name=self.common_name, device=self.device).exclude(pk=self.pk).exists():
            err_msg = (
                f'Credential with common name {self.common_name} '
                f'already exists for device {self.device.unique_name}.')
            raise ValidationError(err_msg)

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.full_clean()
        super().save(*args, **kwargs)