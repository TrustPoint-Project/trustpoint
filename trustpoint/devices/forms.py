from django import forms

from devices import DeviceOnboardingStatus

from .models import Device


class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ['device_name', 'onboarding_protocol', 'domain', 'tags']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance and self.instance.pk and self.instance.device_onboarding_status in [
            DeviceOnboardingStatus.ONBOARDED,
            DeviceOnboardingStatus.ONBOARDING_RUNNING]:
            self.fields['onboarding_protocol'].disabled = True
            self.fields['domain'].disabled = True
