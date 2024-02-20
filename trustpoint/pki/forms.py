"""Module that contains all forms corresponding to the PKI application."""


from django import forms
from django.core.validators import MinLengthValidator


class IssuingCaLocalP12FileForm(forms.Form):
    """Issuing CA file upload form that accepts a PKCS#12 file."""
    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(6)])
    p12 = forms.FileField(label='PKCS#12 File', required=True)
    p12_password = forms.CharField(widget=forms.PasswordInput(), label='PKCS#12 Password', required=False)


class IssuingCaLocalPemFileForm(forms.Form):
    """Issuing CA file upload form that accepts PEM files."""
    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(6)])
    issuing_ca_certificate = forms.FileField(label='Issuing CA Certificate', required=True)
    issuing_ca_certificate_chain = forms.FileField(label='Issuing CA Certificate Chain', required=True)
    issuing_ca_private_key = forms.FileField(label='Issuing CA Private Key', required=True)
    issuing_ca_private_key_password = forms.CharField(
        widget=forms.PasswordInput(), label='Issuing CA Private Key Password', required=False
    )
