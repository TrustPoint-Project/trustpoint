"""This module contains all forms for the Onboarding app."""

from __future__ import annotations

from django import forms
from pki.models import CertificateModel


class BrowserLoginForm(forms.Form):
    onboarding_process_id = forms.IntegerField(label='Onboarding Process ID')
    otp = forms.CharField(widget=forms.PasswordInput(), label='OTP', max_length=24)


class RevokeCertificateForm(forms.ModelForm):
    class Meta:
        model = CertificateModel
        fields = ['revocation_reason']
