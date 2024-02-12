from django.db import models

#class SystemConfig(models.Model):
class NTPConfig(models.Model):
    ntp_server_address = models.GenericIPAddressField(protocol='both')
    
    def __str__(self) -> str:
        return f'{self.ntp_server_address}'
    
class NetworkConfig(models.Model):
    static_ip_address = models.GenericIPAddressField(protocol='both',blank=True,null=True)
    gateway = models.GenericIPAddressField(protocol='both',blank=True,null=True)
    netmask = models.CharField(max_length=20,blank=True,null=True)
    dhcp = models.BooleanField(default=False)
    
    def __str__(self) -> str:
        return f'IP-Address:{self.static_ip_address}, Gateway:{self.gateway}, Netmask:{self.netmask}'
    