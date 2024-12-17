from django import forms
from django.core.exceptions import ValidationError
import ipaddress
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]


class IssueTlsClientCredentialForm(forms.Form):
    common_name = forms.CharField(
        max_length=100,
        label=_('Common Name'),
        initial='',
        required=True,
    )
    pseudonym = forms.CharField(
        max_length=100,
        label=_('Pseudonym'),
        required=True,
        disabled=True
    )
    serial_number = forms.CharField(
        max_length=100,
        label=_('Serial Number'),
        required=True,
        disabled=True
    )
    dn_qualifier = forms.CharField(
        max_length=100,
        label=_('DN Qualifier'),
        required=True,
        disabled=True
    )
    validity = forms.IntegerField(
        label=_('Validity (days)'),
        initial=10,
        required=True
    )

    def clean_validity(self):
        validity = self.cleaned_data['validity']
        if validity <= 0:
            err_msg = _('Validity must be a positive integer.')
            raise ValidationError(err_msg)
        return validity


class IssueTlsServerCredentialForm(forms.Form):

    common_name = forms.CharField(
        max_length=100,
        label=_('Common Name'),
        required=True
    )
    pseudonym = forms.CharField(
        max_length=100,
        label=_('Pseudonym'),
        required=True,
        disabled=True
    )
    serial_number = forms.CharField(
        max_length=100,
        label=_('Serial Number'),
        required=True,
        disabled=True
    )
    dn_qualifier = forms.CharField(
        max_length=100,
        label=_('DN Qualifier'),
        required=True,
        disabled=True
    )
    validity = forms.IntegerField(
        label=_('Validity (days)'),
        initial=10,
        required=True
    )
    ipv4_addresses = forms.CharField(
        label=_('IPv4-Addresses (comma-separated list)'),
        initial='127.0.0.1, ',
        required=False
    )
    ipv6_addresses = forms.CharField(
        label=_('IPv6-Addresses (comma-separated list)'),
        initial='::1, ',
        required=False
    )
    domain_names = forms.CharField(
        label=_('Domain-Names (comma-separated list)'),
        initial='localhost, ',
        required=False
    )

    def clean_validity(self):
        validity = self.cleaned_data['validity']
        if validity <= 0:
            raise ValidationError('Validity must be a positive integer.')
        return validity

    def clean_ipv4_addresses(self):
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv4Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError:
            raise forms.ValidationError('Contains an invalid IPv4-Address.')

    def clean_ipv6_addresses(self):
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv6Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError:
            raise forms.ValidationError('Contains an invalid IPv6-Address.')

    def clean_domain_names(self):
        data = self.cleaned_data['domain_names'].strip()
        if not data:
            return []

        domain_names = data.split(',')
        # TODO(AlexHx8472): Check for valid domains.
        return [domain_name.strip() for domain_name in domain_names if domain_name.strip() != '']


    def clean(self):
        cleaned_data = super().clean()
        ipv4_addresses = cleaned_data.get('ipv4_addresses')
        ipv6_addresses = cleaned_data.get('ipv6_addresses')
        domain_names = cleaned_data.get('domain_names')
        if not (ipv4_addresses or ipv6_addresses or domain_names):
            raise forms.ValidationError('At least one SAN entry is required.')