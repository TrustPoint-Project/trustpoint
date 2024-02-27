"""Module that contains all forms corresponding to the PKI application."""


from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from util.x509.credentials import CredentialsError, CredentialUploadHandler

from .models import IssuingCa

if TYPE_CHECKING:
    from typing import Any

    from util.x509.credentials import P12


class UniqueNameValidationError(ValidationError):
    """Raised when the unique name is already present in the database."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unique name is already taken. Try another one.'
        super().__init__(exc_msg, *args, **kwargs)


class UploadError(ValidationError):
    """Raised the upload failed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Upload failed!'
        super().__init__(exc_msg, *args, **kwargs)


class CleanUniqueNameMixin:
    """Mixin for clean unique name which checks that the unique name is not already present in the database."""

    cleaned_data: dict

    def clean_unique_name(self) -> str:
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


# TODO(Alex): Gather more details in an error case and forward that information to the user through the error messages
class IssuingCaLocalP12FileForm(CleanUniqueNameMixin, IssuingCaUploadForm):
    """Issuing CA file upload form that accepts a PKCS#12 file."""

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(3)])
    p12 = forms.FileField(label='PKCS#12 File', required=True)
    p12_password = forms.CharField(widget=forms.PasswordInput(), label='PKCS#12 Password', required=False)

    def clean(self) -> dict:
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

    unique_name = forms.CharField(max_length=20, required=True, validators=[MinLengthValidator(6)])
    issuing_ca_certificate = forms.FileField(label='Issuing CA Certificate', required=True)
    issuing_ca_certificate_chain = forms.FileField(label='Issuing CA Certificate Chain', required=True)
    issuing_ca_private_key = forms.FileField(label='Issuing CA Private Key', required=True)
    issuing_ca_private_key_password = forms.CharField(
        widget=forms.PasswordInput(), label='Issuing CA Private Key Password', required=False
    )

    def clean(self) -> dict:
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
