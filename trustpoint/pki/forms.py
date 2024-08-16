from __future__ import annotations

from django import forms
from django.utils.translation import gettext_lazy as _

from django.core.exceptions import ValidationError

from pki.initializer.issuing_ca.local.db import LocalUnprotectedIssuingCaFromP12FileInitializer
from pki.models import IssuingCaModel, DomainModel
from pki.validator.field import UniqueNameValidator


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
        label=f'Unique Name ' + UniqueNameValidator.form_label,
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=True,
        validators=[UniqueNameValidator()])

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
        except Exception as exception:
            raise ValidationError(
                'Failed to load PKCS#12 file. Either malformed file or wrong password.',
                code='pkcs12-loading-failed') from exception

        try:
            initializer.save()
        except Exception as exception:
            raise ValidationError(f'{exception}')


class IssuingCaAddFileImportSeparateFilesForm(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label=f'Unique Name ' + UniqueNameValidator.form_label,
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        validators=[UniqueNameValidator()])
    private_key_file = forms.FileField(
        label=_('Private Key File (.key, .pem, .keystore)'), required=True)
    private_key_file_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password'),
        required=False)
    issuing_ca_certificate = forms.FileField(
        label=_('Issuing CA Certificate (.cer, .der, .pem, .p7b)'),
        required=True)
    certificate_chain = forms.FileField(
        label=_('[Optional] Certificate Chain (.pem, .p7b)'), required=False)

    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Choose another one.')
        return unique_name

    # def clean(self):
    #     cleaned_data = super().clean()
    #     unique_name = cleaned_data.get('unique_name')
    #     if unique_name is None:
    #         return
    #
    #     try:
    #         # This should not throw any exceptions, even if invalid data was sent via HTTP POST request.
    #         # However, just in case.
    #         private_key_file_raw = cleaned_data.get('private_key_file').read()
    #         certificate_chain_raw = cleaned_data.get('certificate_chain').read()
    #         issuing_ca_cert_raw = cleaned_data.get('issuing_ca_certificate')
    #         if issuing_ca_cert_raw is not None:
    #             issuing_ca_cert_raw = issuing_ca_cert_raw.read()
    #         private_key_file_password = cleaned_data.get('private_key_file_password')
    #     except Exception:
    #         raise ValidationError(
    #             _('Unexpected error occurred while trying to get file contents. Please see logs for further details.'),
    #             code='unexpected-error')
    #
    #     if private_key_file_password:
    #         try:
    #             private_key_file_password = private_key_file_password.encode()
    #         except Exception:
    #             raise ValidationError('The Private Key File Password contains invalid data, that cannot be encoded in UTF-8.')
    #     else:
    #         pkcs12_password = None
    #
    #     try:
    #         initializer = LocalUnprotectedIssuingCaFromSeparateFilesInitializer(
    #             unique_name=cleaned_data['unique_name'],
    #             private_key_file_raw=private_key_file_raw,
    #             password=private_key_file_password,
    #             issuing_ca_cert_raw=issuing_ca_cert_raw,
    #             certificate_chain_raw=certificate_chain_raw)
    #     except Exception as e:
    #         print(e)
    #         print(traceback.format_exc())
    #         raise ValidationError(
    #             'Failed to load PKCS#12 file. Either malformed file or wrong password.',
    #             code='pkcs12-loading-failed')
    #
    #     try:
    #         initializer.save()
    #     except Exception as e:
    #         print(e)
    #         print(traceback.format_exc())
    #         raise ValidationError('Unexpected Error. Failed to save validated Issuing CA in DB.')


class DomainBaseForm(forms.ModelForm):
    """Base form for DomainModel, containing shared logic and fields."""
    auto_crl = forms.BooleanField(
        label='Generate CRL upon certificate revocation.',
        required=False,
        help_text='Check this box to automatically generate a CRL when a certificate is revoked.'
    )

    class Meta:
        model = DomainModel
        fields = ['unique_name', 'issuing_ca', 'auto_crl']  # Base fields

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['unique_name'].label += UniqueNameValidator.form_label
        if self.instance.pk:  # If updating an existing instance
            self.fields['auto_crl'].initial = self.instance.auto_crl

    def save(self, commit=True):
        domain_instance = super().save(commit=False)
        issuing_ca = domain_instance.issuing_ca

        if issuing_ca:
            issuing_ca.auto_crl = self.cleaned_data['auto_crl']
            issuing_ca.save()

        if commit:
            domain_instance.save()

        return domain_instance


class DomainCreateForm(DomainBaseForm):
    """Form for creating DomainModel instances, includes additional fields."""
    # TODO: validate url_path_segment

    class Meta(DomainBaseForm.Meta):
        fields = DomainBaseForm.Meta.fields


class DomainUpdateForm(DomainBaseForm):
    """Form for updating DomainModel instances."""

    class Meta(DomainBaseForm.Meta):
        fields = DomainBaseForm.Meta.fields


class TrustStoreAddForm(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label=f'Unique Name ' + UniqueNameValidator.form_label,
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=True,
        validators=[UniqueNameValidator()])

    trust_store_file = forms.FileField(label=_('PEM or PKCS#7 File'), required=True)

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
            trust_store_file = cleaned_data.get('trust_store_file').read()
        except Exception:
            raise ValidationError(
                _('Unexpected error occurred while trying to get file contents. Please see logs for further details.'),
                code='unexpected-error')

        try:
            # initializer = TrustStoreInitializer(
            #     unique_name=cleaned_data['unique_name'],
            #     trust_store=trust_store_file)
            pass
        except Exception as e:
            raise ValidationError(
                'Failed to load file. Seems to be malformed.',
                code='trust-store-file-loading-failed')

        try:
            # initializer.save()
            pass
        except Exception:
            raise ValidationError('Unexpected Error. Failed to save validated Trust Store in DB.')



class TruststoresDownloadForm(forms.Form):
    cert_file_container = forms.ChoiceField(
        label=_('Select Truststore Container Type'),
        choices=[
            ('single_file', _('Single File')),
            ('zip', _('Separate Certificate Files (as .zip file)')),
            ('tar_gz', _('Separate Certificate Files (as .tar.gz file)'))
        ],
        initial='single_file',
        required=True)

    cert_file_format = forms.ChoiceField(
        label=_('Select Truststore File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)'))
        ],
        initial='pem',
        required=True)
