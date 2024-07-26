from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _

from django.core.exceptions import ValidationError

from .initializer import LocalUnprotectedIssuingCaFromP12FileInitializer
from .models import IssuingCaModel


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
        label=_('Select Method'),
        choices=[
            ('local_file_import', _('Import a new Issuing CA from file')),
            ('local_request', _('Generate a key-pair and request an Issuing CA certificate')),
            ('remote_est', _('Configure a remote Issuing CA')),
        ],
        initial='local_file_import',
        required=True)


class IssuingCaFileTypeSelectForm(forms.Form):

    # TODO: do we need .jks? Java Keystore
    method_select = forms.ChoiceField(
        label=_('File Type'),
        choices=[
            ('pkcs_12', _('PKCS#12')),
            ('other', _('PEM, PKCS#1, PKCS#7, PKCS#8')),
        ],
        initial='pkcs_12',
        required=True)


class IssuingCaAddFileImportPkcs12Form(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label='Unique Name (Issuing CA)',
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=True)

    pkcs12_file = forms.FileField(label=_('PKCS#12 File (.p12, .pfx)'), required=True)
    pkcs12_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] PKCS#12 password'),
        required=False)

    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Choose another one.')
        return unique_name

    def clean(self):
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')
        if unique_name is None:
            return

        try:
            # This should not throw any exceptions, even if invalid data was sent via HTTP POST request.
            # However, just in case.
            pkcs12_raw = cleaned_data.get('pkcs12_file').read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
        except Exception:
            raise ValidationError(
                _('Unexpected error occurred while trying to get file contents. Please see logs for further details.'),
                code='unexpected-error')

        if pkcs12_password:
            try:
                pkcs12_password = pkcs12_password.encode()
            except Exception:
                raise ValidationError('The PKCS#12 password contains invalid data, that cannot be encoded in UTF-8.')
        else:
            pkcs12_password = None

        try:
            initializer = LocalUnprotectedIssuingCaFromP12FileInitializer(
                unique_name=cleaned_data['unique_name'],
                p12=pkcs12_raw,
                password=pkcs12_password)
        except Exception as e:
            print(e)
            print(type(e))
            raise ValidationError(
                'Failed to load PKCS#12 file. Either malformed file or wrong password.',
                code='pkcs12-loading-failed')

        try:
            initializer.save()
        except Exception:
            raise ValidationError('Unexpected Error. Failed to save validated Issuing CA in DB.')


class IssuingCaAddFileImportOtherForm(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label='Unique Name (Issuing CA)',
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}))
    private_key_file = forms.FileField(
        label=_('Private key file (.key, .pem, .keystore)'), required=True)
    private_key_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private key file password'),
        required=False)
    cert_chain = forms.FileField(
        label=_(
            'Certificate chain (.pem, .p7b, .p7c)'),
        required=True)


class DomainModelForm(forms.ModelForm):

    class Meta:
        fields = ['unique_name', 'url_path_segment', 'issuing_ca']

    # TODO: use form instead of CreateView and fields directly
    # TODO: validate url_path_segment
