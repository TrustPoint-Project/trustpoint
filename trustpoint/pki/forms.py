from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from core.serializer import CredentialSerializer, CertificateSerializer, PrivateKeySerializer, \
    CertificateCollectionSerializer
from trustpoint.views.base import LoggerMixin
from pki.models import CertificateModel, IssuingCaModel
from core.validator.field import UniqueNameValidator
from cryptography.hazmat.primitives import hashes


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

    @LoggerMixin.log_exceptions
    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Unique name is already taken. Choose another one.')
        return unique_name

    @LoggerMixin.log_exceptions
    def clean(self):
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')

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
            err_msg = _('Failed to parse and load the uploaded file. Either wrong password or corrupted file.')
            raise ValidationError(err_msg) from exception

        try:
            IssuingCaModel.create_new_issuing_ca(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
                issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED
            )
        # TODO(AlexHx8472): Filter credentials and check if any issuing ca corresponds to it.
        # TODO(AlexHx8472): If it does get and display the name of the issuing ca in the message.
        # TODO(AlexHx8472): If not, give information about the credential usage that is already in the db.
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception


class IssuingCaAddFileImportSeparateFilesForm(LoggerMixin, forms.Form):

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
    ca_certificate = forms.FileField(
        label=_('Issuing CA Certificate (.cer, .der, .pem, .p7b, .p7c)'),
        required=True)
    ca_certificate_chain = forms.FileField(
        label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c).'), required=False)

    @LoggerMixin.log_exceptions
    def clean_unique_name(self) -> str:
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError('Issuing CA with the provided name already exists.')
        return unique_name

    @LoggerMixin.log_exceptions
    def clean_private_key_file(self) -> PrivateKeySerializer:
        private_key_file = self.cleaned_data.get('private_key_file')
        private_key_file_password = self.data.get('private_key_file_password') \
            if self.data.get('private_key_file_password') else None

        print('pw type')
        print(private_key_file_password)

        if not private_key_file:
            err_msg = 'No private key file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if private_key_file.size > max_size:
            err_msg = 'Private key file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        try:
            return PrivateKeySerializer(private_key_file.read(), private_key_file_password)
        except Exception as exception:
            err_msg = _('Failed to parse the private key file. Either wrong password or file corrupted.')
            raise ValidationError(err_msg) from exception

    @LoggerMixin.log_exceptions
    def clean_ca_certificate(self) -> CertificateSerializer:
        ca_certificate = self.cleaned_data['ca_certificate']

        if not ca_certificate:
            err_msg = 'No Issuing CA file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if ca_certificate.size > max_size:
            err_msg = 'Issuing CA file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)


        try:
            certificate_serializer = CertificateSerializer(ca_certificate.read())
            print(certificate_serializer)
        except Exception as exception:
            err_msg = _('Failed to parse the Issuing CA certificate. Seems to be corrupted.')
            raise ValidationError(err_msg) from exception
        print(certificate_serializer)

        certificate_in_db = CertificateModel.get_cert_by_sha256_fingerprint(
            certificate_serializer.as_crypto().fingerprint(algorithm=hashes.SHA256()).hex())
        if certificate_in_db:
            issuing_ca_in_db = IssuingCaModel.objects.get(certificate=certificate_in_db)
            if issuing_ca_in_db:
                err_msg = (
                    f'Issuing CA {issuing_ca_in_db.unique_name} is already configured '
                    'with the same Issuing CA certificate.')
                raise ValidationError(err_msg)

        return certificate_serializer

    @LoggerMixin.log_exceptions
    def clean_ca_certificate_chain(self) -> None | CertificateCollectionSerializer:
        ca_certificate_chain = self.cleaned_data['ca_certificate_chain']

        # TODO(AlexHx8472): Validate if full chain is available
        if ca_certificate_chain:
            try:
                return CertificateCollectionSerializer(ca_certificate_chain.read())
            except Exception as exception:
                raise ValidationError('Failed to parse the Issuing CA certificate chain. Seems to be corrupted.')

        return None


    @LoggerMixin.log_exceptions
    def clean(self):
        try:
            cleaned_data = super().clean()
            unique_name = cleaned_data.get('unique_name')
            private_key_file = cleaned_data.get('private_key_file')
            ca_certificate = cleaned_data.get('ca_certificate')
            ca_certificate_chain = cleaned_data.get('ca_certificate_chain') \
                if cleaned_data.get('ca_certificate_chain') else None

            if not unique_name or not private_key_file or not ca_certificate:
                return

            credential_serializer = CredentialSerializer(
                (
                    private_key_file,
                    ca_certificate,
                    ca_certificate_chain
                )
            )


            IssuingCaModel.create_new_issuing_ca(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
                issuing_ca_type=IssuingCaModel.IssuingCaTypeChoice.LOCAL_UNPROTECTED
            )
        # TODO(AlexHx8472): Filter credentials and check if any issuing ca corresponds to it.
        # TODO(AlexHx8472): If it does get and display the name of the issuing ca in the message.
        # TODO(AlexHx8472): If not, give information about the credential usage that is already in the db.
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception
