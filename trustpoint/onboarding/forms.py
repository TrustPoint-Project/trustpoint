"""This module contains all forms for the Onboarding app."""
from django import forms
from pki.models import RevokedCertificate


class RevokeCertificateForm(forms.ModelForm):
    class Meta:
        model = RevokedCertificate
        fields = ['revocation_reason']
