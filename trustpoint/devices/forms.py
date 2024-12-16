from django import forms
from django.core.exceptions import ValidationError


class IssueTlsClientCredentialForm(forms.Form):
    common_name = forms.CharField(
        max_length=100,
        label='Common Name',
        required=True,
    )
    pseudonym = forms.CharField(
        max_length=100,
        label='Pseudonym',
        required=True,
        disabled=True
    )
    serial_number = forms.CharField(
        max_length=100,
        label='Serial Number',
        required=True,
        disabled=True
    )
    dn_qualifier = forms.CharField(
        max_length=100,
        label='DN Qualifier',
        required=True,
        disabled=True
    )
    validity = forms.IntegerField(
        label='Validity (days)',
        required=True
    )

    def clean_validity(self):
        validity = self.cleaned_data['validity']
        if validity <= 0:
            raise ValidationError('Validity must be a positive integer.')
        return validity

