from django import forms

from devices.models import DeviceModel

class AddDeviceForm(forms.ModelForm):

    class Meta:
        model = DeviceModel
        fields = [
            'unique_name',
            'serial_number',
            'primary_domain',
            'secondary_domains'
        ]
