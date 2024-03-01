"""Model definitions"""
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


# class SystemConfig(models.Model):
class NTPConfig(models.Model):
    """NTP Configuration model"""
    ntp_server_address = models.GenericIPAddressField(protocol='both')

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.ntp_server_address}'


class LoggingConfig(models.Model):
    """Logging Configuration model"""
    logging_server_address = models.GenericIPAddressField(protocol='both')
    logging_server_port = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(65536)])

    class LogTypes(models.TextChoices):
        """Types of logging protocols"""
        SYSLOG = '1', 'Syslog'
        GRAYLOG = '2', 'Graylog'
        SPLUNK = '3', 'Splunk'

    class NetworkTypes(models.TextChoices):
        """Types of network protocols"""
        TCP = '1', 'TCP'
        UDP = '2', 'UDP'

    logging_type = models.CharField(max_length=3, choices=LogTypes.choices, default=LogTypes.SYSLOG)
    network_type = models.CharField(max_length=2, choices=NetworkTypes.choices, default=NetworkTypes.TCP)

    def __str__(self) -> str:
        """Output as string"""
        return f'{self.logging_server_address}:{self.logging_server_port}'


class NetworkConfig(models.Model):
    """Network Configuration model"""
    static_ip_address = models.GenericIPAddressField(protocol='both', blank=True, null=True)
    gateway = models.GenericIPAddressField(protocol='both', blank=True, null=True)
    netmask = models.CharField(max_length=20, blank=True, null=True)
    dhcp = models.BooleanField(default=False)

    def __str__(self) -> str:
        """Output as string"""
        return f'IP-Address:{self.static_ip_address}, Gateway:{self.gateway}, Netmask:{self.netmask}'
