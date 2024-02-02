from django import forms
from .models import LocalIssuingCa, IssuingCa


class IssuingCaP12Form(forms.ModelForm):
    class Meta:
        model = IssuingCa
        fields = ['unique_name']


class IssuingCaPemForm(forms.ModelForm):
    class Meta:
        model = IssuingCa
        fields = ['unique_name']


class IssuingCaLocalP12FileForm(forms.Form):
    p12 = forms.FileField(label='PKCS#12 File', required=True)
    p12_password = forms.CharField(widget=forms.PasswordInput(), label='PKCS#12 Password', required=False)


class IssuingCaLocalPemFileForm(forms.Form):
    issuing_ca_certificate = forms.FileField(label='Issuing CA Certificate', required=True)
    issuing_ca_certificate_chain = forms.FileField(label='Issuing CA Certificate Chain', required=True)
    issuing_ca_private_key = forms.FileField(label='Issuing CA Private Key', required=True)
    issuing_ca_private_key_password = forms.CharField(
        widget=forms.PasswordInput(),
        label='Issuing CA Private Key Password',
        required=False)
