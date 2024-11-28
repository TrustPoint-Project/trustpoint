"""Forms definition"""
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from django import forms
from django.utils.translation import gettext_lazy as _
from pki.util.keys import AutoGenPkiKeyAlgorithm

from .models import LoggingConfig, NetworkConfig, NTPConfig, SecurityConfig
from .security import SecurityModeChoices


class NTPConfigForm(forms.ModelForm):
    class Meta:
        model = NTPConfig
        fields = ['ntp_server_address', 'server_port', 'sync_interval', 'enabled']
        widgets = {
            'ntp_server_address': forms.TextInput(attrs={'placeholder': 'Enter NTP server (e.g., pool.ntp.org)'}),
            'server_port': forms.NumberInput(attrs={'min': 1, 'max': 65535}),
            'sync_interval': forms.NumberInput(attrs={'min': 1}),
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

        if self.instance and self.instance.pk:
            if self.instance.auto_gen_pki:
                # Visually disable auto_gen_pki_key_algorithm if auto_gen_pki is enabled
                self.fields['auto_gen_pki_key_algorithm'].widget.attrs['disabled'] = 'disabled'

        self.helper = FormHelper()

        self.helper.layout = Layout(
            Fieldset(
                _('Security level presets'),
                'security_mode',
            ),
            Fieldset(
                _('Advanced security settings'),
                'auto_gen_pki',
                'auto_gen_pki_key_algorithm',
            )
        )

    security_mode = forms.ChoiceField(choices=SecurityModeChoices.choices,
                                      widget=forms.RadioSelect(),
                                      label='')

    auto_gen_pki = forms.BooleanField(required=False, label=_('Enable local auto-generated PKI'),
                                widget=forms.CheckboxInput(
                                    attrs={'data-sl-defaults': '[true, true, false, false, false]',
                                           'data-hide-at-sl': '[false, false, true, true, true]',
                                           'data-more-secure': 'false'}))

    auto_gen_pki_key_algorithm = forms.ChoiceField(choices=AutoGenPkiKeyAlgorithm.choices,
                                                   label=_('Key Algorithm for auto-generated PKI'),
                                                   required=False,
                                                   widget=forms.Select(
                                                       attrs={'data-hide-at-sl': '[false, false, true, true, true]'}))

    class Meta:
        """Meta class"""
        model = SecurityConfig
        fields = ['security_mode',
                  'auto_gen_pki',
                  'auto_gen_pki_key_algorithm']

    def clean_auto_gen_pki_key_algorithm(self):
        """Keep the current value of `auto_gen_pki_key_algorithm` from the instance if the field was disabled."""
        form_value = self.cleaned_data.get('auto_gen_pki_key_algorithm')
        if form_value is None:
            return self.instance.auto_gen_pki_key_algorithm if self.instance else AutoGenPkiKeyAlgorithm.RSA2048
        return form_value
