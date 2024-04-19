"""Module that contains all forms corresponding to the PKI application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.forms import ModelChoiceField
from django.forms.widgets import DateTimeInput
from django.utils.timezone import now
from datetime import timedelta

from util.x509.credentials import CredentialsError, CredentialUploadHandler
from util.protocols.est_remote import ESTProtocolHandler
from util.x509.enrollment import Enrollment

from .models import IssuingCa, RootCa

if TYPE_CHECKING:
    from typing import Any

    from util.x509.credentials import P12


class UniqueNameValidationError(ValidationError):
    """Raised when the unique name is already present in the database."""

    def __init__(self: UniqueNameValidationError, *args: Any, **kwargs: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unique name is already taken. Try another one.'
        super().__init__(exc_msg, *args, **kwargs)


class UploadError(ValidationError):
    """Raised the upload failed."""

    def __init__(self: UploadError, *args: Any, **kwargs: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Upload failed!'
        super().__init__(exc_msg, *args, **kwargs)

class CreateError(ValidationError):
    """Raised if the creation of a (root) CA failed."""

    def __init__(self: CreateError, *args: Any, **kwargs: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'CA creation failed!'
        super().__init__(exc_msg, *args, **kwargs)

class CleanUniqueNameMixin:
    """Mixin for clean unique name which checks that the unique name is not already present in the database."""

    cleaned_data: dict

    def clean_unique_name(self: CleanUniqueNameMixin) -> str:
        """Checks that the unique name is not already present in the database.

        Raises:
            UniqueNameValidationError:
                Raised if the unique name is already present in the database.
        """
        unique_name = self.cleaned_data['unique_name']
        if IssuingCa.objects.filter(unique_name=unique_name).exists():
            raise UniqueNameValidationError
        return unique_name


class IssuingCaUploadForm(forms.Form):
    """Form for uploading an Issuing CA through files."""

    # Disables crispy alert header (msg of ValidationError in clean())
    non_field_errors: bool = False
    normalized_p12: P12

    unique_name: forms.CharField

class TruststoreUploadForm(forms.Form):
    """Form for uploading a truststore through files."""

    # Disables crispy alert header (msg of ValidationError in clean())
    non_field_errors: bool = False

    unique_name: forms.CharField


# TODO(Alex): Gather more details in an error case and forward that information to the user through the error messages
class IssuingCaLocalP12FileForm(CleanUniqueNameMixin, IssuingCaUploadForm):
    """Issuing CA file upload form that accepts a PKCS#12 file."""

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])
    p12 = forms.FileField(label='PKCS#12 File', required=True)
    p12_password = forms.CharField(widget=forms.PasswordInput(), label='PKCS#12 Password', required=False)

    def clean(self: IssuingCaLocalP12FileForm) -> dict:
        """Tries to normalize the P12 file.

        Returns:
            dict:
                cleaned data (django)

        Raises:
            UploadError:
                Raised if parsing, normalization and or storage failed.
        """
        cleaned_data = super().clean()
        p12 = cleaned_data.get('p12').read()
        p12_password = cleaned_data.get('p12_password').encode()

        try:
            self.normalized_p12 = CredentialUploadHandler.parse_and_normalize_p12(p12, p12_password)
        except CredentialsError as exception:
            self.add_error('p12', 'Failed to parse PKCS#12 file. Invalid password or PKCS#12 data.')
            self.add_error('p12_password', 'Failed to parse PKCS#12 file. Invalid password or PKCS#12 data.')
            raise UploadError from exception

        if self.errors:
            raise UploadError

        return cleaned_data



class IssuingCaLocalPemFileForm(CleanUniqueNameMixin, IssuingCaUploadForm):
    """Issuing CA file upload form that accepts PEM files."""

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])
    issuing_ca_certificate = forms.FileField(label='Issuing CA Certificate', required=True)
    issuing_ca_certificate_chain = forms.FileField(label='Issuing CA Certificate Chain', required=True)
    issuing_ca_private_key = forms.FileField(label='Issuing CA Private Key', required=True)
    issuing_ca_private_key_password = forms.CharField(
        widget=forms.PasswordInput(), label='Issuing CA Private Key Password', required=False
    )

    def clean(self: IssuingCaLocalPemFileForm) -> dict:
        """Tries to normalize the PEM files into a P12 file.

        Returns:
            dict:
                cleaned data (django)

        Raises:
            UploadError:
                Raised if parsing, normalization and or storage failed.
        """
        cleaned_data = super().clean()
        issuing_ca_certificate = cleaned_data.get('issuing_ca_certificate').read()
        issuing_ca_certificate_chain = cleaned_data.get('issuing_ca_certificate_chain').read()
        issuing_ca_private_key = cleaned_data.get('issuing_ca_private_key').read()
        issuing_ca_private_key_password = cleaned_data.get('issuing_ca_private_key_password').encode()

        try:
            cert = CredentialUploadHandler.parse_pem_cert(issuing_ca_certificate)
        except CredentialsError as exception:
            self.add_error('issuing_ca_certificate', 'Failed to serialize PEM certificate.')
            raise UploadError from exception

        try:
            cert_chain = CredentialUploadHandler.parse_pem_cert_chain(cert, issuing_ca_certificate_chain)
        except CredentialsError as exception:
            self.add_error('issuing_ca_certificate_chain', 'Failed to serialize PEM certificate chain.')
            raise UploadError from exception

        try:
            key = CredentialUploadHandler.parse_pem_key(issuing_ca_private_key, issuing_ca_private_key_password)
        except CredentialsError as exception:
            self.add_error('issuing_ca_private_key', 'Failed to serialize key file. Wrong password?')
            self.add_error('issuing_ca_private_key_password', 'Failed to serialize key file. Wrong password?')
            raise UploadError from exception

        try:
            self.normalized_p12 = CredentialUploadHandler.parse_and_normalize_x509_crypto(cert, cert_chain, key)
        except CredentialsError as exception:
            msg = 'Unexpected error occurred. Please try again.'
            self.add_error('issuing_ca_certificate', msg)
            self.add_error('issuing_ca_certificate_chain', msg)
            self.add_error('issuing_ca_private_key', msg)
            self.add_error('issuing_ca_private_key_password', msg)
            raise UploadError from exception

        if self.errors:
            raise UploadError

        return cleaned_data

class IssuingCaESTForm(CleanUniqueNameMixin, IssuingCaUploadForm):
    """Retrieve an issuing CA certificate from a remote CA via EST"""

    est_url = forms.CharField(max_length=100, required=True)
    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])
    common_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])

    est_user_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])
    est_password = forms.CharField(
        widget=forms.PasswordInput(), label='Issuing CA Private Key Password', required=False
    )
    KEY_TYPES =  ( ('RSA_2048','RSA 2048'),
                  ('RSA_4096','RSA 4096'),
                  ('ECC_256','Secp256r1'),
                  ('ECC_384','Secp348r1'),
                )

    key_type = forms.CharField(widget=forms.Select(choices=KEY_TYPES))

    def clean(self) -> dict[str, Any]:
        """Calls ESTProtocolHandler in clean method. This ensures that protocol errors can be displayed in the form

        Raises:
            UploadError: Import of certificate failed

        Returns:
            dict[str, Any]: returns the cleaned data
        """
        cleaned_data = super().clean()

        est_url = cleaned_data.get('est_url')
        unique_name = cleaned_data.get('unique_name')
        common_name = cleaned_data.get('common_name')

        est_user_name = cleaned_data.get('est_user_name')
        est_password = cleaned_data.get('est_password')
        key_type = cleaned_data.get('key_type')

        try:
            ESTProtocolHandler.est_get_ca_certificate(est_user_name,est_password,est_url,unique_name,common_name,key_type)
        except ValueError as e:
            self.add_error('est_url', 'Error in EST Protocol'+ str(e))
            raise UploadError from e

        return cleaned_data

class RootCaChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.unique_name} - {obj.ca_type}"

class IssuingCaLocalSignedForm(CleanUniqueNameMixin, IssuingCaUploadForm):
    """Issuing CA form for locally signed CAs."""

    unique_name = forms.CharField(max_length=20,
                                  required=True,
                                  validators=[MinLengthValidator(3)])
    common_name = forms.CharField(max_length=20, required=True)
    root_ca = RootCaChoiceField(
        queryset=RootCa.objects.all(),
        label="Root CA / Issuer DN",
        empty_label="Select a Root CA / Issuer DN",
        to_field_name="unique_name",
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True
    )
    not_valid_before = forms.DateTimeField(
        initial=now(),
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}, format='%Y-%m-%dT%H:%M'),
        label='Not Valid Before',
        required=True
    )
    not_valid_after = forms.DateTimeField(
        initial=lambda: now() + timedelta(days=365),  # default one year from now
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}, format='%Y-%m-%dT%H:%M'),
        label='Not Valid After',
        required=True
    )

    def __init__(self, *args, **kwargs):
        super(IssuingCaLocalSignedForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        unique_name = cleaned_data.get('unique_name')
        common_name = cleaned_data.get('common_name')
        root_ca = cleaned_data.get('root_ca')
        not_valid_before = cleaned_data.get('not_valid_before')
        not_valid_after = cleaned_data.get('not_valid_after')

        try:
            Enrollment.generate_local_signed_sub_ca(unique_name=unique_name,
                                                    common_name=common_name,
                                                    root_ca_unique_name=root_ca.unique_name,
                                                    not_valid_before=not_valid_before,
                                                    not_valid_after=not_valid_after,
                                                    subject_password=None,
                                                    issuer_password=None,
                                                    config_type=IssuingCa.ConfigType.F_SELF)
        except ValueError as e:
            self.add_error('unique_name', 'Error while generating a subordinate CA'+ str(e))
            raise CreateError from e

        return cleaned_data

class AddTruststoreForm(CleanUniqueNameMixin, TruststoreUploadForm):
    """Truststore form for adding new Truststores"""

    truststore_certificate_file = forms.FileField(label='Upload Truststore (.pem file)', required=False)
    truststore_certificate_text = forms.CharField(label='Or enter Truststore Certificate Text', widget=forms.Textarea,
                                                  required=False)
    def clean(self):
        cleaned_data = super().clean()

        truststore_certificate_file = cleaned_data.get('truststore_certificate_file')
        truststore_certificate_text = cleaned_data.get('truststore_certificate_text')

        # Validate that either file or text is provided, but not both
        if truststore_certificate_file and truststore_certificate_text:
            raise ValidationError("Please provide either a file or text for the truststore certificate, not both.")
        if not truststore_certificate_file and not truststore_certificate_text:
            raise ValidationError("Please provide a truststore certificate either as a file or as text.")

        return cleaned_data