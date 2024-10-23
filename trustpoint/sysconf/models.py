"""Model definitions"""
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm

from sysconf.security import SecurityFeatures, SecurityModeChoices
from sysconf.security.manager import SecurityManager


# class SystemConfig(models.Model):
class NTPConfig(models.Model):
    """NTP Configuration model"""
    ntp_server_address = models.GenericIPAddressField(protocol='both')

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.ntp_server_address}'


class LoggingConfig(models.Model):
    """Logging Configuration model"""
    logging_server_address = models.GenericIPAddressField(_('Logging server address'), protocol='both')
    logging_server_port = models.IntegerField(
        _('Logging server port'), validators=[MinValueValidator(0), MaxValueValidator(65536)]
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

    logging_type = models.CharField(_('Logging type'), max_length=3, choices=LogTypes.choices, default=LogTypes.SYSLOG)
    network_type = models.CharField(_('Network type'), max_length=2, choices=NetworkTypes.choices, default=NetworkTypes.TCP)

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.logging_server_address}:{self.logging_server_port}'


class NetworkConfig(models.Model):
    """Network Configuration model"""
    static_ip_address = models.GenericIPAddressField(_('Static IP address'), protocol='both', blank=True, null=True)
    gateway = models.GenericIPAddressField(_('Gateway'), protocol='both', blank=True, null=True)
    netmask = models.CharField(_('Netmask'), max_length=20, blank=True, null=True)
    dhcp = models.BooleanField(default=False)

    def __str__(self) -> str:
        """Output as string"""
        return f'IP-Address:{self.static_ip_address}, Gateway:{self.gateway}, Netmask:{self.netmask}'

class SecurityConfig(models.Model):
    """Security Configuration model"""

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices.choices, default=SecurityModeChoices.LOW)

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(max_length=12,
                                                  choices=AutoGenPkiKeyAlgorithm,
                                                  default=AutoGenPkiKeyAlgorithm.RSA2048)

    _original_values = {}

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.security_mode}'

    def save(self, *args, **kwargs):
        """Override the save method to enforce allowed security levels"""
        if not SecurityManager.is_feature_allowed(SecurityFeatures.AUTO_GEN_PKI, self.security_mode):
            self.auto_gen_pki = False

        super().save(*args, **kwargs)


# -------------
