from django import forms

from .models import Device


class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['device_name', 'onboarding_protocol', 'domain', 'tags']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance and self.instance.pk and self.instance.device_onboarding_status in [
            Device.DeviceOnboardingStatus.ONBOARDED,
            Device.DeviceOnboardingStatus.ONBOARDING_RUNNING]:
            self.fields['domain'].disabled = True
