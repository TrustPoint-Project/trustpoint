from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _


class CertificateDownloadForm(forms.Form):
    cert_file_container = forms.ChoiceField(
        label=_('Select Certificate Container Type'),
        choices=[
            ('single_file', _('Single File')),
            ('zip', _('Separate Certificate Files (as .zip file)')),
            ('tar_gz', _('Separate Certificate Files (as .tar.gz file)'))
        ],
        initial='single_file',
        required=True)

    cert_chain_incl = forms.ChoiceField(
        label=_('Select Included Certificates'),
        choices=[
            ('cert_only', _('Selected certificates only')),
            ('chain_incl', _('Include certificate chains'))
        ],
        initial='selected_cert_only',
        required=True
    )

    cert_file_format = forms.ChoiceField(
        label=_('Select Certificate File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)'))
        ],
        initial='pem',
        required=True)


class IssuingCaAddMethodSelectForm(forms.Form):

    method_select = forms.ChoiceField(
        label='Select Method',
        choices=[
            ('local_file_pem', _('Import a new Issuing CA from file')),
            ('local_request', _('Generate a key-pair and request an Issuing CA certificate')),
            ('remote_est', _('Configure a remote Issuing CA')),
        ],
        initial='single_file',
        required=True)


class IssuingCaAddFileImportForm(forms.Form):
    # Disables crispy alert header (msg of ValidationError in clean())
    # non_field_errors: bool = False

    unique_name = forms.CharField(
        max_length=256,
        label='Unique Name (Issuing CA)',
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}))
    private_key_file = forms.FileField(
        label=_('Private Key File (Formats: DER, PEM, PKCS#1, PKCS#8, PKCS#12)'), required=True)
    private_key_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password, if the private key file is encrypted.'),
        required=False)
    cert_chain = forms.FileField(
        label=_('[Optional] Certificate Chain, if not contained in private key file. (Formats: PEM, PKCS#7)'),
        required=False)
    issuing_ca_certificate = forms.FileField(
        label=_(
            '[Optional] Issuing CA Certificate, if not contained in private key file or certificate chain. '
            '(Formats: PEM, PKCS#7)'),
        required=False)


