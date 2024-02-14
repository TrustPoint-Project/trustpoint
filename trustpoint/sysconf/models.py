from django.db import models

#class SystemConfig(models.Model):
class NTPConfig(models.Model):
    ntp_server_address = models.GenericIPAddressField(protocol='both')
    
    def __str__(self) -> str:
        return f'{self.ntp_server_address}'
    
class LoggingConfig(models.Model):
    logging_server_address = models.GenericIPAddressField(protocol='both')
    logging_server_port = models.IntegerField(max_length=5)
    class LogTypes(models.TextChoices):
        SYSLOG = "1", "Syslog"
        GRAYLOG = "2", "Graylog"
        SPLUNK = "3", "Splunk"
    
    
    logging_type = models.CharField(
        max_length=3,
        choices=LogTypes.choices,
        default=LogTypes.SYSLOG
    )
    
    def __str__(self) -> str:
        return f'{self.logging_server_address}:{self.logging_server_port}'
    
class NetworkConfig(models.Model):
    static_ip_address = models.GenericIPAddressField(protocol='both',blank=True,null=True)
    gateway = models.GenericIPAddressField(protocol='both',blank=True,null=True)
    netmask = models.CharField(max_length=20,blank=True,null=True)
    dhcp = models.BooleanField(default=False)
    
    def __str__(self) -> str:
        return f'IP-Address:{self.static_ip_address}, Gateway:{self.gateway}, Netmask:{self.netmask}'
    