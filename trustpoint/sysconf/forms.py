"""Forms definition"""
from django import forms
from django.utils.translation import gettext_lazy as _

from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Fieldset

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()

        self.helper.layout = Layout(
            Fieldset(
                _('Security level presets'),
                'security_mode',
            ),
            Fieldset(
                _('Advanced security settings'),
                'enable_local_root_ca',	
                #'local_root_ca_alg_type'
            )
        )


    security_mode = forms.ChoiceField(choices=SecurityConfig.SecurityModeChoices.choices,
                                      widget=forms.RadioSelect(),
                                      label='')
    
    enable_local_root_ca = forms.BooleanField(required=False, label=_('Enable Local Root CA'),
                                widget=forms.CheckboxInput(
                                    attrs={'data-sl-defaults': '[true,false,false]',
                                           'data-more-secure': 'false'}))

    class Meta:
        """Meta class"""
        model = SecurityConfig
        fields = ['security_mode','enable_local_root_ca']
        labels = {
            'security_mode': _('Security Level'),
            'enable_local_root_ca': _('Enable Local Root CA'),
        }


