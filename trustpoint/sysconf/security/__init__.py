from enum import Enum
from django.db import models
from django.utils.translation import gettext_lazy as _

class SecurityModeChoices(models.TextChoices):
    """Types of security modes"""
    DEV = '0', _('Testing env')
    LOW = '1', _('Basic')
    MEDIUM = '2', _('Medium')
    HIGH = '3', _('High')
    HIGHEST = '4', _('Highest')

class SecurityFeatures(Enum):
    """A class that defines various security features used throughout the application."""
    AUTO_GEN_PKI = 'Auto-Generated PKI'
    LOG_ACCESS = 'Log Access'
