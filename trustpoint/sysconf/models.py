"""Model definitions"""
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from trustpoint.validators import validate_isidentifer
from django.utils import timezone


# class SystemConfig(models.Model):
class NTPConfig(models.Model):
    """NTP Configuration model"""
    ntp_server_address = models.GenericIPAddressField(protocol='both')

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.ntp_server_address}'


class LoggingConfig(models.Model):
    """Logging Configuration model"""
    logging_server_address = models.GenericIPAddressField(_("Logging server address"), protocol='both')
    logging_server_port = models.IntegerField(
        _("Logging server port"), validators=[MinValueValidator(0), MaxValueValidator(65536)]
    )

    class LogTypes(models.TextChoices):
        """Types of logging protocols"""
        SYSLOG = '1', 'Syslog'
        GRAYLOG = '2', 'Graylog'
        SPLUNK = '3', 'Splunk'

    class NetworkTypes(models.TextChoices):
        """Types of network protocols"""
        TCP = '1', 'TCP'
        UDP = '2', 'UDP'

    logging_type = models.CharField(_("Logging type"), max_length=3, choices=LogTypes.choices, default=LogTypes.SYSLOG)
    network_type = models.CharField(_("Network type"), max_length=2, choices=NetworkTypes.choices, default=NetworkTypes.TCP)

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.logging_server_address}:{self.logging_server_port}'


class NetworkConfig(models.Model):
    """Network Configuration model"""
    static_ip_address = models.GenericIPAddressField(_("Static IP address"), protocol='both', blank=True, null=True)
    gateway = models.GenericIPAddressField(_("Gateway"), protocol='both', blank=True, null=True)
    netmask = models.CharField(_("Netmask"), max_length=20, blank=True, null=True)
    dhcp = models.BooleanField(default=False)

    def __str__(self) -> str:
        """Output as string"""
        return f'IP-Address:{self.static_ip_address}, Gateway:{self.gateway}, Netmask:{self.netmask}'

class SecurityConfig(models.Model):
    """Security Configuration model"""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes"""
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices.choices, default=SecurityModeChoices.LOW)
    enable_local_root_ca = models.BooleanField(default=False)


    def __str__(self) -> str:
        """Output as string"""
        return f'{self.security_mode}:{self.onboarding_methods}'


# -------------
