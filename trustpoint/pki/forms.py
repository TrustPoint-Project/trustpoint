from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from core.serializer import CredentialSerializer
from pki.initializer import (
    UnprotectedFileImportLocalIssuingCaFromSeparateFilesInitializer,
)
from trustpoint.views.base import LoggerMixin
from pki.models import IssuingCaModel, DomainModel
from core.validator.field import UniqueNameValidator


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


class IssuingCaAddFileImportPkcs12Form(LoggerMixin, forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label=_('Unique Name') + ' ' + UniqueNameValidator.form_label,
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

    @LoggerMixin.log_exceptions
    def clean(self):
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')
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
            credential_serializer = CredentialSerializer(pkcs12_raw, pkcs12_password)
        except Exception as exception:
            raise ValidationError(
                _('Failed to parse and load the uploaded file. Either wrong password or corrupted file.')
            ) from exception

        try:
            IssuingCaModel.create_new_issuing_ca(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
                issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED
            )
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception


class IssuingCaAddFileImportSeparateFilesForm(forms.Form):

    unique_name = forms.CharField(
        max_length=256,
        label=_('Unique Name') + ' ' + UniqueNameValidator.form_label,
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
