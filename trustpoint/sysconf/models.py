"""Model definitions"""
from typing import Any
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm

from sysconf.security import SecurityFeatures, SecurityModeChoices
from sysconf.security.manager import SecurityManager


# class SystemConfig(models.Model):
class NTPConfig(models.Model):
    """Enhanced NTP Configuration model"""
    ntp_server_address = models.CharField(
        max_length=255,
        validators=[
            RegexValidator(
                regex=r'^([a-zA-Z0-9.-]+|\d{1,3}(\.\d{1,3}){3})$',
                message="Enter a valid IPv4/IPv6 address or hostname."
            )
        ],
        help_text="IP address or hostname of the NTP server"
    )
    server_port = models.PositiveIntegerField(
        default=123,
        help_text="Port used to connect to the NTP server (default is 123)."
    )
    enabled = models.BooleanField(
        default=False,
        help_text="Enable or disable NTP synchronization for this configuration."
    )
    last_sync_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="The timestamp of the last successful synchronization with the NTP server."
    )
    sync_status = models.CharField(
        max_length=32,
        choices=[
            ('success', 'Success'),
            ('failure', 'Failure'),
            ('pending', 'Pending'),
        ],
        default='pending',
        help_text="The status of the last synchronization attempt ('Success', 'Failure', or 'Pending')."
    )

    class Meta:
        verbose_name = "NTP Configuration"
        verbose_name_plural = "NTP Configurations"

    def __str__(self):
        return f"{self.ntp_server_address} (Enabled: {self.enabled})"


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
    auto_gen_pki_key_algorithm = models.CharField(max_length=24,
                                                  choices=AutoGenPkiKeyAlgorithm,
                                                  default=AutoGenPkiKeyAlgorithm.RSA2048)

    _original_values: None | dict = None

    def update_original_values(self):
        """Set the original values, which are used to detect changes"""
        self._original_values['security_mode'] = self.security_mode
        self._original_values['auto_gen_pki'] = self.auto_gen_pki

    @property
    def original_values(self) -> Any:
        """Get the original value for a given setting"""
        return self._original_values

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._original_values = {}
        super().__init__(*args, **kwargs)
        self.update_original_values()

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.security_mode}'

    def save(self, *args, **kwargs):
        """Override the save method to enforce allowed security levels"""
        if not SecurityManager.is_feature_allowed(
                SecurityFeatures.AUTO_GEN_PKI,
                SecurityModeChoices(self.security_mode)):
            self.auto_gen_pki = False

        super().save(*args, **kwargs)
