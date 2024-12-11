from __future__ import annotations

from django.db import models    # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]


class OnboardingStatus(models.IntegerChoices):
    """Possible onboarding states that a device can be in."""

    NOT_ONBOARDED = 1, _('Pending')
    ONBOARDING_RUNNING = 2, _('Running')
    ONBOARDED = 3, _('Onboarded')
    ONBOARDING_FAILED = 4, _('Failed')
    REVOKED = 5, _('Revoked')


class ManualOnboardingProcess(models.Model):

    onboarding_status = models.IntegerField(verbose_name=_('Onboarding Status'), choices=OnboardingStatus)


class BrowserOnboardingProcess(models.Model):

    onboarding_status = models.IntegerField(verbose_name=_('Onboarding Status'), choices=OnboardingStatus)

class TrustpointClientOnboardingProcess(models.Model):

    onboarding_status = models.IntegerField(verbose_name=_('Onboarding Status'), choices=OnboardingStatus)
