"""This module contains all forms for the Onboarding app."""
from django import forms
from pki.models import CertificateModel


class RevokeCertificateForm(forms.ModelForm):
    class Meta:
        model = CertificateModel
        fields = ['revocation_reason']
