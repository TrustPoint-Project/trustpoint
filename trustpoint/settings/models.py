"""Models concerning the Trustpoint settings."""

from typing import Any

from django.db import models
from django.utils.translation import gettext_lazy as _
from util.keys import AutoGenPkiKeyAlgorithm

class SecurityConfig(models.Model):
    """Security Configuration model"""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes"""
        DEV = '0', _('Testing env')
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')
        HIGHEST = '4', _('Highest')


    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices.choices, default=SecurityModeChoices.LOW)

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(max_length=24,
                                                  choices=AutoGenPkiKeyAlgorithm,
                                                  default=AutoGenPkiKeyAlgorithm.RSA2048)


    def __str__(self) -> str:
        """Output as string"""
        return f'{self.security_mode}'
