from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from pki.initializer import (
    UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer,
    UnprotectedFileImportLocalIssuingCaFromSeparateFilesInitializer,
)
from pki.models import DomainModel, IssuingCaModel
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

    auto_crl = forms.BooleanField(label='Generate CRL upon certificate revocation.', initial=True, required=False)

    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Choose another one.')
        return unique_name

    def clean(self):
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')
        auto_crl = cleaned_data.get('auto_crl')
        if unique_name is None:
            raise ValidationError('No Unique Name was specified.')

        try:
            pkcs12_raw = cleaned_data.get('pkcs12_file').read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
        except Exception:
            # This should not throw any exceptions, this data should always be available and readable.
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
            initializer = UnprotectedFileImportLocalIssuingCaFromPkcs12Initializer(
                unique_name=cleaned_data['unique_name'],
                p12=pkcs12_raw,
                password=pkcs12_password,
                auto_crl=auto_crl)
        except Exception as exception:
            raise ValidationError(
                'Failed to load PKCS#12 file. Either malformed file or wrong password.',
                code='pkcs12-loading-failed') from exception

        initializer.initialize()
        initializer.save()


class IssuingCaAddFileImportSeparateFilesForm(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label=f'Unique Name ' + UniqueNameValidator.form_label,
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        validators=[UniqueNameValidator()])
    private_key_file = forms.FileField(
        label=_('Private Key File (.key, .pem)'), required=True)
    private_key_file_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password'),
        required=False)
    issuing_ca_certificate = forms.FileField(
        label=_('Issuing CA Certificate (.cer, .der, .pem, .p7b, .p7c)'),
        required=True)
    certificate_chain = forms.FileField(
        label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c) '), required=False)
    
    auto_crl = forms.BooleanField(label='Generate CRL upon certificate revocation.', initial=True, required=False)

    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Choose another one.')
        return unique_name

    def clean(self):
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')
        auto_crl = cleaned_data.get('auto_crl')
        if unique_name is None:
            return

        try:
            # This should not throw any exceptions, even if invalid data was sent via HTTP POST request.
            # However, just in case.
            private_key_file_raw = cleaned_data.get('private_key_file').read()
            certificate_chain_raw = cleaned_data.get('certificate_chain')

            if certificate_chain_raw is not None:
                certificate_chain_raw = certificate_chain_raw.read()

            issuing_ca_cert_raw = cleaned_data.get('issuing_ca_certificate').read()
            private_key_file_password = cleaned_data.get('private_key_file_password')
        except Exception:
            raise ValidationError(
                _('Unexpected error occurred while trying to get file contents. Please see logs for further details.'),
                code='unexpected-error')

        if private_key_file_password:
            try:
                private_key_file_password = private_key_file_password.encode()
            except Exception:
                raise ValidationError('The Private Key File Password contains invalid data, that cannot be encoded in UTF-8.')
        else:
            private_key_file_password = None

        try:
            initializer = UnprotectedFileImportLocalIssuingCaFromSeparateFilesInitializer(
                unique_name=cleaned_data['unique_name'],
                auto_crl=auto_crl,
                private_key_raw=private_key_file_raw,
                password=private_key_file_password,
                issuing_ca_certificate_raw=issuing_ca_cert_raw,
                additional_certificates_raw=certificate_chain_raw)
        except Exception as e:
            raise ValidationError(
                'Failed to load CA from files. Either malformed file or wrong password.',
                code='pkcs12-loading-failed')

        initializer.initialize()
        initializer.save()


class CRLGenerationTimeDeltaForm(forms.ModelForm):

    class Meta:
        model = IssuingCaModel
        fields = ['next_crl_generation_time',]
        labels = {'next_crl_generation_time': '',}


class CRLAutoGenerationForm(forms.ModelForm):

    class Meta:
        model = IssuingCaModel
        fields = ['auto_crl']


class DomainBaseForm(forms.ModelForm):
    """Base form for DomainModel, containing shared logic and fields."""
    class Meta:
        model = DomainModel
        fields = ['unique_name', 'issuing_ca']  # Base fields

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['unique_name'].label += UniqueNameValidator.form_label

    def save(self, commit=True):
        domain_instance = super().save(commit=False)

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
