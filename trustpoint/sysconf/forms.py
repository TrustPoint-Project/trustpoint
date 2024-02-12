from django import forms
from .models import NetworkConfig, NTPConfig

class NTPConfigForm(forms.ModelForm):
    class Meta:
        model = NTPConfig
        fields = '__all__'

class NetworkConfigForm(forms.ModelForm):
   
    class Meta:
        model = NetworkConfig
        fields = '__all__'
        