"""This module contains all forms for the Onboarding app."""

from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _


class BrowserLoginForm(forms.Form):
    device_id = forms.IntegerField(label='Device ID')
    otp = forms.CharField(widget=forms.PasswordInput(), label='OTP', max_length=24)
