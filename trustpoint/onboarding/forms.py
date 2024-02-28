"""This module contains all forms for the Onboarding app."""

from django import forms


class OnboardingStartForm(forms.Form):
    """Form for starting an onboarding process with a device name."""
    name = forms.CharField(label='Device Name', max_length=32, required=True)
