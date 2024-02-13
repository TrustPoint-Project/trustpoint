from django import forms
from .models import NetworkConfig, NTPConfig
from django.utils.translation import gettext_lazy as _

class NTPConfigForm(forms.ModelForm):
    class Meta:
        model = NTPConfig
        fields = '__all__'
        labels = {
            "ntp_server_address": _("NTP Server Address"),
        }

class NetworkConfigForm(forms.ModelForm):
   
    class Meta:
        model = NetworkConfig
        fields = '__all__'
        labels = {
            "static_ip_address": _("Static IP Address"),
            "dhcp": _("DHCP"),
            "netmask": _("Netmask"),
            "gateway": _("Gateway")
        }