"""Defines forms for the devices app.

This module contains the DeviceForm class for creating and updating Device
instances, with additional logic for handling field state based on the device's
onboarding status.
"""
from __future__ import annotations

from typing import Any, ClassVar

from django import forms
from pki.models import DomainModel

from devices import DeviceOnboardingStatus

from .models import Device


class DeviceForm(forms.ModelForm):
    """Form for the Device model.

    This form allows users to create or update `Device` instances. It includes
    logic to disable certain fields based on the device's onboarding status.

    Attributes:
        Meta (class): Contains metadata about the form, such as the associated
            model and fields.
    """

    class Meta:
        """Metadata for the DeviceForm.

        Specifies the model and fields included in the form.
        """
        model = Device
        fields: ClassVar[list[str]] = ['device_name', 'domains', 'tags']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the DeviceForm.

        Disables the `onboarding_protocol` and `domain` fields if the device
        is in an onboarding or onboarded state.

        Args:
            *args (Any): Positional arguments passed to the form.
            **kwargs (Any): Keyword arguments passed to the form.
        """
        super().__init__(*args, **kwargs)

        if (
            self.instance
            and self.instance.pk
        ):
            self.fields['domains'].disabled = True


class DomainSelectionForm(forms.Form):
    """Form to select multiple domains."""
    domains = forms.ModelMultipleChoiceField(
        queryset=DomainModel.objects.all(),
        widget=forms.CheckboxSelectMultiple(),
        label='Select Domains',
        required=False
    )

class DeviceConfigForm(forms.ModelForm):
    """Form to configure the device."""
    class Meta:
        model = Device
        fields = ['device_serial_number']
        widgets = {
            'device_serial_number': forms.TextInput(),
        }
