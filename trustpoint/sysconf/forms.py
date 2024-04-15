"""Forms definition"""
from django import forms
from django.utils.translation import gettext_lazy as _

from .models import LoggingConfig, NetworkConfig, NTPConfig, SecurityConfig


class NTPConfigForm(forms.ModelForm):
    """NTP configuration form"""
    class Meta:
        """Meta class"""
        model = NTPConfig
        fields = ['ntp_server_address']
        labels = {
            'ntp_server_address': _('NTP Server Address'),
        }


class NetworkConfigForm(forms.ModelForm):
    """Network configuration model form"""
    class Meta:
        """Meta class"""
        model = NetworkConfig
        fields = ['static_ip_address','gateway','netmask','dhcp']
        labels = {
            'static_ip_address': _('Static IP Address'),
            'dhcp': _('DHCP'),
            'netmask': _('Netmask'),
            'gateway': _('Gateway'),
        }


class LoggingConfigForm(forms.ModelForm):
    """Logging configuration model form"""

    class Meta:
        """Meta class"""
        model = LoggingConfig
        fields = ['logging_server_address','logging_server_port','logging_type','network_type']
        labels = {
            'logging_server_address': _('Logging Server Address'),
            'logging_server_port': _('Logging Server Port'),
            'logging_type': _('Logging Protocol'),
            'network_type': _('Network Protocol'),
        }

class SecurityConfigForm(forms.ModelForm):
    """Security configuration model form"""

    security_mode = forms.ChoiceField(choices=SecurityConfig.SecurityModeChoices.choices,
                                      widget=forms.RadioSelect(),
                                      label=_('Security level preset'))

    class Meta:
        """Meta class"""
        model = SecurityConfig
        fields = ['security_mode','enable_local_root_ca','local_root_ca_alg_type']
        labels = {
            'security_mode': _('Security Level'),
            'enable_local_root_ca': _('Enable Local Root CA'),
            'local_root_ca_alg_type': _('Local Root CA Algorithm Type'),
        }


