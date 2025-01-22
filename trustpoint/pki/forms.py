"""Module for managing PKI-related forms in the TrustPoint application."""

from __future__ import annotations

from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)
from core.validator.field import UniqueNameValidator
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from pki.initializer.truststore.truststore import TrustStoreInitializer
from pki.models import CertificateModel, IssuingCaModel
from pki.models.truststore import TruststoreModel
from trustpoint.views.base import LoggerMixin


class TruststoreAddForm(forms.Form):
    """Form for adding a new truststore.

    This form handles the creation of a truststore by validating the unique name,
    intended usage, and uploaded file. It ensures the unique name is not already
    used and validates the truststore file content before saving.

    Attributes:
        unique_name (CharField): A unique name for the truststore.
        intended_usage (ChoiceField): Specifies the intended usage of the truststore.
        trust_store_file (FileField): The PEM or PKCS#7 file to be uploaded.
    """
    unique_name = forms.CharField(
        max_length=256,
        label=_('Unique Name') + ' ' + UniqueNameValidator.form_label,
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=True,
        validators=[UniqueNameValidator()])

    intended_usage = forms.ChoiceField(
        choices=TruststoreModel.IntendedUsage.choices,
        label=_('Intended Usage'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True
    )

    trust_store_file = forms.FileField(label=_('PEM or PKCS#7 File'), required=True)

    @LoggerMixin.log_exceptions
    def clean_unique_name(self) -> str:
        """Validates the uniqueness of the truststore name.

        Raises:
            ValidationError: If the name is already used by an existing truststore.
        """
        unique_name = self.cleaned_data['unique_name']
        if TruststoreModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Truststore with the provided name already exists.'
            raise ValidationError(error_message)
        return unique_name

    @LoggerMixin.log_exceptions
    def clean(self) -> None:
        """Cleans and validates the form data.

        Ensures the uploaded file can be read and validates the unique name
        and intended usage fields. If validation passes, initializes and saves
        the truststore.

        Raises:
            ValidationError: If the truststore file cannot be read, the unique name
            is not unique, or an unexpected error occurs during initialization.
        """
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')
        intended_usage = cleaned_data.get('intended_usage')

        try:
            trust_store_file = cleaned_data.get('trust_store_file').read()
        except (OSError, AttributeError) as original_exception:
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.')
            raise ValidationError(error_message, code='unexpected-error') from original_exception

        try:
            initializer = TrustStoreInitializer(
                unique_name=unique_name,
                intended_usage=int(intended_usage),
                trust_store=trust_store_file)
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception

        try:
            initializer.save()
        except Exception as original_exception:
            error_message = 'Unexpected Error. Failed to save validated Trust Store in DB.'
            raise ValidationError(error_message) from original_exception

class TruststoreDownloadForm(forms.Form):
    """Form for downloading truststores in various formats.

    This form provides options to customize the download of truststores, allowing
    users to specify the container type, inclusion of certificate chains, and
    the file format. It ensures flexibility in exporting truststores for
    various use cases and environments.

    Attributes:
        cert_file_container (ChoiceField): Specifies the container type for the truststore.
            - `single_file`: The entire truststore in a single file.
            - `zip`: Certificates as separate files in a `.zip` archive.
            - `tar_gz`: Certificates as separate files in a `.tar.gz` archive.
        cert_chain_incl (ChoiceField): Specifies whether to include certificate chains.
            - `cert_only`: Only the selected certificates.
            - `chain_incl`: Include certificate chains.
        cert_file_format (ChoiceField): Specifies the file format for the truststore.
            - `pem`: PEM format (.pem, .crt, .ca-bundle).
            - `der`: DER format (.der, .cer).
            - `pkcs7_pem`: PKCS#7 format in PEM encoding (.p7b, .p7c, .keystore).
            - `pkcs7_der`: PKCS#7 format in DER encoding (.p7b, .p7c, .keystore).
    """
    cert_file_container = forms.ChoiceField(
        label=_('Select Truststore Container Type'),
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
        label=_('Select Truststore File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)'))
        ],
        initial='pem',
        required=True)

class CertificateDownloadForm(forms.Form):
    """Form for downloading certificates in various formats.

    This form allows users to customize the download options for certificates,
    including the container type, inclusion of certificate chains, and the
    file format. It provides flexibility to download certificates in the
    desired structure and format for different use cases.

    Attributes:
        cert_file_container (ChoiceField): Specifies the container type for the downloaded certificates.
            - `single_file`: All certificates in a single file.
            - `zip`: Certificates as separate files in a `.zip` archive.
            - `tar_gz`: Certificates as separate files in a `.tar.gz` archive.
        cert_chain_incl (ChoiceField): Specifies whether to include certificate chains.
            - `cert_only`: Only the selected certificates.
            - `chain_incl`: Include certificate chains.
        cert_file_format (ChoiceField): Specifies the file format for the certificates.
            - `pem`: PEM format (.pem, .crt, .ca-bundle).
            - `der`: DER format (.der, .cer).
            - `pkcs7_pem`: PKCS#7 format in PEM encoding (.p7b, .p7c, .keystore).
            - `pkcs7_der`: PKCS#7 format in DER encoding (.p7b, .p7c, .keystore).
    """
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
    """Form for selecting the method to add an Issuing Certificate Authority (CA).

    This form provides options to choose the method for adding a new Issuing CA.
    Users can select between importing from a file, generating a key pair and
    requesting an Issuing CA certificate, or configuring a remote Issuing CA.

    Attributes:
        method_select (ChoiceField): A dropdown to select the method for adding an Issuing CA.
            - `local_file_import`: Import a new Issuing CA from a file.
            - `local_request`: Generate a key-pair and request a certificate.
            - `remote_est`: Configure a remote Issuing CA.
    """

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
    """Form for selecting the file type when importing an Issuing CA.

    This form allows users to choose the type of file to use for importing an
    Issuing Certificate Authority (CA). Supported formats include PKCS#12 and
    other common certificate formats such as PEM, PKCS#1, PKCS#7, and PKCS#8.

    Attributes:
        method_select (ChoiceField): A dropdown to select the file type for the Issuing CA.
    """

    # TODO(AlexHx8472): do we need .jks? Java Keystore
    method_select = forms.ChoiceField(
        label=_('File Type'),
        choices=[
            ('pkcs_12', _('PKCS#12')),
            ('other', _('PEM, PKCS#1, PKCS#7, PKCS#8')),
        ],
        initial='pkcs_12',
        required=True)


class IssuingCaAddFileImportPkcs12Form(LoggerMixin, forms.Form):
    """Form for importing an Issuing CA using a PKCS#12 file.

    This form allows the user to upload a PKCS#12 file containing the private key
    and certificate chain, along with an optional password. It validates the
    uploaded file and its contents and ensures the unique name is not already
    used by another Issuing CA.

    Attributes:
        unique_name (CharField): A unique name for the Issuing CA.
        pkcs12_file (FileField): The PKCS#12 file containing the private key and certificates.
        pkcs12_password (CharField): An optional password for the PKCS#12 file.
    """

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
        """Validates the unique name to ensure it is not already in use.

        Raises:
            ValidationError: If the unique name is already associated with an existing Issuing CA.
        """
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Unique name is already taken. Choose another one.'
            raise ValidationError(error_message)
        return unique_name

    @LoggerMixin.log_exceptions
    def clean(self) -> None:
        """Cleans and validates the entire form.

        This method performs additional validation on the cleaned data to ensure
        all required fields are valid and consistent. It checks the uploaded PKCS#12
        file and its password (if provided) and validates that the unique name
        does not conflict with existing entries. Any issues during validation
        raise appropriate errors.

        Raises:
            ValidationError: If the data is invalid, such as when the unique name
            is already taken or the PKCS#12 file cannot be read or parsed.
        """
        cleaned_data = super().clean()
        unique_name = cleaned_data.get('unique_name')

        try:
            pkcs12_raw = cleaned_data.get('pkcs12_file').read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
        except (OSError, AttributeError) as original_exception:
            # These exceptions are likely to occur if the file cannot be read or is missing attributes.
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.')
            raise ValidationError(error_message, code='unexpected-error') from original_exception

        if pkcs12_password:
            try:
                pkcs12_password = pkcs12_password.encode()
            except Exception as original_exception:
                error_message = 'The PKCS#12 password contains invalid data, that cannot be encoded in UTF-8.'
                raise ValidationError(error_message) from original_exception
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
    """Form for importing an Issuing CA using separate files.

    This form allows the user to upload a private key file, its password (optional),
    an Issuing CA certificate file, and an optional certificate chain. The form
    validates the uploaded files, ensuring they are correctly formatted, within
    size limits, and not already associated with an existing Issuing CA.

    Attributes:
        unique_name (CharField): A unique name for the Issuing CA.
        private_key_file (FileField): The private key file (.key, .pem).
        private_key_file_password (CharField): An optional password for the private key.
        ca_certificate (FileField): The Issuing CA certificate file (.cer, .der, .pem, .p7b, .p7c).
        ca_certificate_chain (FileField): An optional certificate chain file.
    """

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
        """Validates the unique name to ensure it does not already exist in the database.

        Raises:
            ValidationError: If an Issuing CA with the provided name already exists.
        """
        unique_name = self.cleaned_data['unique_name']
        if IssuingCaModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Issuing CA with the provided name already exists.'
            raise ValidationError(error_message)
        return unique_name

    @LoggerMixin.log_exceptions
    def clean_private_key_file(self) -> PrivateKeySerializer:
        """Validates and parses the uploaded private key file.

        This method checks if the private key file is provided, ensures it meets
        size constraints, and validates its contents. If a password is provided,
        it is used to decrypt the private key. Raises validation errors for missing,
        oversized, or corrupted private key files.

        Returns:
            PrivateKeySerializer: A serializer containing the parsed private key.

        Raises:
            ValidationError: If the private key file is missing, too large, or
            corrupted, or if the password is invalid or incompatible.
        """
        private_key_file = self.cleaned_data.get('private_key_file')
        private_key_file_password = self.data.get('private_key_file_password') \
            if self.data.get('private_key_file_password') else None

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
        """Validates and parses the uploaded Issuing CA certificate file.

        This method ensures the provided Issuing CA certificate file is valid and
        not already associated with an existing Issuing CA in the database. If the
        file is too large, corrupted, or already in use, a validation error is raised.

        Returns:
            CertificateSerializer: A serializer containing the parsed certificate.

        Raises:
            ValidationError: If the file is missing, too large, corrupted, or already
            associated with an existing Issuing CA.
        """
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
        except Exception as exception:
            err_msg = _('Failed to parse the Issuing CA certificate. Seems to be corrupted.')
            raise ValidationError(err_msg) from exception

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
        """Validates and parses the uploaded Issuing CA certificate chain file.

        This method checks if the optional certificate chain file is provided.
        If present, it validates and attempts to parse the file into a collection
        of certificates. Raises a validation error if parsing fails or the file
        appears corrupted.

        Returns:
            CertificateCollectionSerializer: A serializer containing the parsed
            certificate chain if provided.

        Raises:
            ValidationError: If the certificate chain cannot be parsed.
        """
        ca_certificate_chain = self.cleaned_data['ca_certificate_chain']

        # TODO(AlexHx8472): Validate if full chain is available
        if ca_certificate_chain:
            try:
                return CertificateCollectionSerializer(ca_certificate_chain.read())
            except Exception as original_exception:
                err_msg = 'Failed to parse the Issuing CA certificate chain. Seems to be corrupted.'
                raise ValidationError(err_msg) from original_exception

        return None


    @LoggerMixin.log_exceptions
    def clean(self) -> None:
        """Cleans and validates the form data.

        This method performs additional validation on the provided data,
        such as ensuring the unique name, private key file, and certificates
        are valid. It also initializes and saves the issuing CA configuration
        if all checks pass.

        Raises:
            ValidationError: If the form data is invalid or there is an error during processing.
        """
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
