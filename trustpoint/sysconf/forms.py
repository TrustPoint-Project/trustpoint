from django import forms
from .models import NetworkConfig, NTPConfig, LoggingConfig
from django.utils.translation import gettext_lazy as _


class NTPConfigForm(forms.ModelForm):
    class Meta:
        model = NTPConfig
        fields = '__all__'
        labels = {
            'ntp_server_address': _('NTP Server Address'),
        }


class NetworkConfigForm(forms.ModelForm):
    class Meta:
        model = NetworkConfig
        fields = '__all__'
        labels = {
            'static_ip_address': _('Static IP Address'),
            'dhcp': _('DHCP'),
            'netmask': _('Netmask'),
            'gateway': _('Gateway'),
        }


class LoggingConfigForm(forms.ModelForm):
    class Meta:
        model = LoggingConfig
        fields = '__all__'
        labels = {
            'logging_server_address': _('Logging Server Address'),
            'logging_server_port': _('Logging Server Port'),
            'logging_type': _('Logging Protocol'),
            'network_type': _('Network Protocol'),
        }
