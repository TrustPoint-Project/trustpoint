from __future__ import annotations

import datetime
import logging
import secrets
from typing import Any

from django.db import models
from django.db.models import UniqueConstraint
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from core.validator.field import UniqueNameValidator
from django.core.exceptions import ValidationError

from pki.models import CertificateModel, DomainModel, CredentialModel, IssuingCaModel

from pki.models.credential import CredentialModel

logger = logging.getLogger(__name__)

class DeviceModel(models.Model):

    objects: models.Manager[DeviceModel]

    def __str__(self) -> str:
        return f'DeviceModel(unique_name={self.unique_name})'


    class OnboardingProtocol(models.IntegerChoices):
        """Supported Onboarding Protocols."""

        NO_ONBOARDING = 0, _('No Onboarding')
        MANUAL = 1, _('Manual download')
        CLI = 2, _('Device CLI')
        TP_CLIENT = 3, _('Trustpoint Client')
        AOKI = 4, _('AOKI')
        BRSKI = 5, _('BRSKI')


    class OnboardingStatus(models.IntegerChoices):
        """Onboarding status."""

        NO_ONBOARDING = 0, _('No Onboarding')
        PENDING = 1, _('Pending')
        ONBOARDED = 2, _('Onboarded')

    id = models.AutoField(primary_key=True)
    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default='New-Device', validators=[UniqueNameValidator()]
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


class RemoteDeviceCredentialDownloadModel(models.Model):
    """Model to associate a credential model with an OTP and token for unauthenticated remoted download."""
    BROWSER_MAX_OTP_ATTEMPTS = 3
    TOKEN_VALIDITY = datetime.timedelta(minutes=3)

    issued_credential_model = models.OneToOneField(IssuedCredentialModel, on_delete=models.CASCADE)
    otp = models.CharField(_('OTP'), max_length=32, default='')
    device = models.ForeignKey(DeviceModel, on_delete=models.CASCADE)
    attempts = models.IntegerField(_('Attempts'), default=0)
    download_token = models.CharField(_('Download Token'), max_length=64, default='')
    token_created_at = models.DateTimeField(_('Token Created'), null=True)

    def __str__(self) -> str:
        """Return a string representation of the model."""
        return f'RemoteDeviceCredentialDownloadModel(credential={self.issued_credential_model.id})'

    def save(self, *args: dict, **kwargs: dict) -> None:
        """Generates a new random OTP on initial save of the model."""
        if not self.otp:
            self.otp = secrets.token_urlsafe(8)
        super().save(*args, **kwargs)

    def get_otp_display(self) -> str:
        """Return the OTP in the format 'credential_id.otp' for display within the admin view."""
        if not self.otp or self.otp == '-':
            return 'OTP no longer valid'
        return f'{self.issued_credential_model.id}.{self.otp}'

    def check_otp(self, otp: str) -> bool:
        """Check if the provided OTP matches the stored OTP."""
        if not self.otp or self.otp == '-':
            return False
        matches = otp == self.otp
        if not matches:
            self.attempts += 1
            log_msg = (
                f'Incorrect OTP attempt {self.attempts} for browser credential download '
                f'for device {self.device.unique_name} (credential id={self.issued_credential_model.id})'
            )
            logger.warning(log_msg)

            if self.attempts >= self.BROWSER_MAX_OTP_ATTEMPTS:
                self.otp = '-'
                self.delete()
                logger.warning('Too many incorrect OTP attempts. Download invalidated.')
            else:
                self.save()
            return False

        log_msg = (
            f'Correct OTP entered for browser credential download for device {self.device.unique_name}'
            f'(credential id={self.issued_credential_model.id})'
        )
        logger.info(log_msg)
        self.otp = '-'
        self.download_token = secrets.token_urlsafe(32)
        self.token_created_at = timezone.now()
        self.save()
        return True

    def check_token(self, token: str) -> bool:
        """Check if the provided token matches the stored token and whether it is still valid."""
        if not self.download_token or not self.token_created_at:
            return False
        if timezone.now() - self.token_created_at > self.TOKEN_VALIDITY:
            self.delete()
            return False

        return token == self.download_token


class TrustpointClientOnboardingProcessModel(models.Model):
    """Holds all current Trustpoint-Client onboarding processes."""

    id = models.AutoField(primary_key=True)

    class AuthenticationMethod(models.IntegerChoices):

        PASSWORD_BASED_MAC = 0, _('Password Based Mac')
        IDEVID = 1, _('Initial Device Identity (IDevID)')

    auth_method = models.IntegerField(verbose_name=_('Authentication Method'), choices=AuthenticationMethod)
    device = models.ForeignKey(DeviceModel, verbose_name=_('Device'), on_delete=models.PROTECT)
    password = models.CharField(max_length=64, verbose_name=_('Password'), null=True, blank=True)

