"""App (package) that is responsible for all device related operations and views."""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _

from devices.exceptions import UnknownOnboardingStatusError


class DeviceOnboardingStatus(models.TextChoices):
    """Device Onboarding Status."""

    NOT_ONBOARDED = 'P', _('Pending')
    ONBOARDING_RUNNING = 'R', _('Running')
    ONBOARDED = 'O', _('Onboarded')
    ONBOARDING_FAILED = 'F', _('Failed')
    REVOKED = 'D', _('Revoked')

    @classmethod
    def get_color(cls: type[DeviceOnboardingStatus], choice: DeviceOnboardingStatus | str) -> str:
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
