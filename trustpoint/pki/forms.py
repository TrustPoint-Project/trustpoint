"""Module that contains all forms corresponding to the PKI application."""


from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from util.x509.credentials import CredentialUploadHandler

from .models import IssuingCa

if TYPE_CHECKING:
    from util.x509.credentials import P12


class IssuingCaLocalP12FileForm(forms.Form):
    """Issuing CA file upload form that accepts a PKCS#12 file."""

    # Disables crispy alert header (msg of ValidationError in clean())
    non_field_errors: bool = False
    # The heading is hidden. However, if we decide to active it, the following is the global error message (heading).
    heading_error_message = 'Upload failed!'
    normalized_p12: P12

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(6)])
    p12 = forms.FileField(label='PKCS#12 File', required=True)
    p12_password = forms.CharField(widget=forms.PasswordInput(), label='PKCS#12 Password', required=False)

    def clean_unique_name(self):
        unique_name = self.cleaned_data['unique_name']
        if IssuingCa.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Try another one.')
        return unique_name

    def clean(self):
        cleaned_data = super().clean()
        p12 = cleaned_data.get('p12').read()
        p12_password = cleaned_data.get('p12_password').encode()

        # noinspection PyBroadException
        try:
            self.normalized_p12 = CredentialUploadHandler.parse_and_normalize_p12(p12, p12_password)
        except Exception:
            self.add_error('p12', 'Failed to parse PKCS#12 file. Invalid password or PKCS#12 data.')
            self.add_error('p12_password', 'Failed to parse PKCS#12 file. Invalid password or PKCS#12 data.')
            raise ValidationError(self.heading_error_message)

        if self.errors:
            raise ValidationError(self.heading_error_message)

        return cleaned_data


class IssuingCaLocalPemFileForm(forms.Form):
    """Issuing CA file upload form that accepts PEM files."""

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(6)])
    issuing_ca_certificate = forms.FileField(label='Issuing CA Certificate', required=True)
    issuing_ca_certificate_chain = forms.FileField(label='Issuing CA Certificate Chain', required=True)
    issuing_ca_private_key = forms.FileField(label='Issuing CA Private Key', required=True)
    issuing_ca_private_key_password = forms.CharField(
        widget=forms.PasswordInput(), label='Issuing CA Private Key Password', required=False
    )
