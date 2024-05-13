"""Module that contains all models corresponding to the PKI app."""


from __future__ import annotations

from pathlib import Path
from typing import Any
from cryptography.x509 import Certificate as CryptoCert
from cryptography.hazmat.primitives.serialization import pkcs12

from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from django.db import models
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from trustpoint.validators import validate_isidentifer
from datetime import timedelta

class Certificate(models.Model):
    """X509 Certificate Model"""

    class Version(models.IntegerChoices):
        v1 = 0, _('Version 1')
        v2 = 1, _('Version 2')
        v3 = 2, _('Version 3')

    version = models.PositiveSmallIntegerField(choices=Version)

class RootCa(models.Model):
    """Root CA model."""

    class CaType(models.TextChoices):
        """Supported curves."""

        SECP256R1 = 'SECP256R1', _('SECP256R1')
        SECP384R1 = 'SECP384R1', _('SECP384R1')
        RSA2048 = 'RSA2048', _('RSA2048')
        RSA4096 = 'RSA4096', _('RSA4096')


    unique_name = models.CharField(
        max_length=100, validators=[MinLengthValidator(3), validate_isidentifer], unique=True
    )
    common_name = models.CharField(max_length=65536, default='', blank=True)
    not_valid_before = models.DateTimeField(default=timezone.now)
    not_valid_after = models.DateTimeField(default=timezone.now() + timedelta(days=365*1))

    ca_type = models.CharField(max_length=9, choices=CaType.choices, default='RSA2048')

    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self: RootCa) -> str:
        """Human-readable representation of the RootCa model instance.

        Returns:
            str:    Human-readable representation of the RootCa model instance.
        """
        return f'RootCa({self.unique_name}, {self.common_name})'

    def get_delete_url(self: RootCa) -> str:
        """Creates the URL for the corresponding delete-view.

        Returns:
            str:    URL for the delete-view.
        """
        return f'delete/{self.pk}/'

    def get_details_url(self: RootCa) -> str:
        """Creates the URL for the corresponding details-view.

        Returns:
            str:    URL for the details-view.
        """
        return f'details/{self.pk}/'

    def as_django_ninja_schema(self):
        pass


class IssuingCa(models.Model):
    """Issuing CA model."""

    class KeyType(models.TextChoices):
        """Supported key-types."""

        RSA = 'RSA', _('RSA')
        ECC = 'ECC', _('ECC')

    class Curves(models.TextChoices):
        """Supported curves."""

        SECP256R1 = 'SECP256R1', _('SECP256R1')
        SECP384R1 = 'SECP384R1', _('SECP384R1')

    class Localization(models.TextChoices):
        """Determines if the Issuing CA is locally or remotely available.

        Note:
            L:  Certificate, certificate chain and key-pair are locally available.
                Certificates can be issued locally.
            R:  The Issuing CA is external.
                Certificate request messages are generated and send to the CA to issue certificates.
        """

        L = 'L', _('Local')
        R = 'R', _('Remote')

    class ConfigType(models.TextChoices):
        """Confing."""

        F_P12 = 'F_P12', _('File Import - PKCS#12')
        F_PEM = 'F_PEM', _('File Import - PEM')
        F_SELF = 'F_SELF', _('Locally signed')
        F_EST = 'F_EST', _('Cert. Import - EST')

    unique_name = models.CharField(
        max_length=100, validators=[MinLengthValidator(3), validate_isidentifer], unique=True
    )

    common_name = models.CharField(max_length=65536, default='', blank=True)
    not_valid_before = models.DateTimeField()
    not_valid_after = models.DateTimeField()

    key_type = models.CharField(max_length=3, choices=KeyType)
    key_size = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(65536)])
    curve = models.CharField(max_length=10, choices=Curves, default='', blank=True)
    localization = models.CharField(max_length=1, choices=Localization)
    config_type = models.CharField('Configuration Type', max_length=10, choices=ConfigType)

    p12 = models.FileField(
        verbose_name='PKCS#12 File (.p12, .pfx)',
    )
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self: IssuingCa) -> str:
        """Human-readable representation of the IssuingCa model instance.

        Returns:
            str:    Human-readable representation of the IssuingCa model instance.
        """
        return f'IssuingCa({self.unique_name}, {self.localization})'

    def get_delete_url(self: IssuingCa) -> str:
        """Creates the URL for the corresponding delete-view.

        Returns:
            str:    URL for the delete-view.
        """
        return f'delete/{self.pk}/'

    def get_details_url(self: IssuingCa) -> str:
        """Creates the URL for the corresponding details-view.

        Returns:
            str:    URL for the details-view.
        """
        return f'details/{self.pk}/'

    def as_django_ninja_schema(self):
        pass

    def get_crypto_cert_chain(self: IssuingCa) -> list[CryptoCert]:
        with Path(self.p12.path).open('rb') as f:
            pkcs12_bytes = f.read()

        p12 = pkcs12.load_pkcs12(pkcs12_bytes, b'')
        return [cert.certificate for cert in p12.additional_certs]


# noinspection PyUnusedLocal
@receiver(models.signals.post_delete)
def auto_delete_file_on_delete(sender: models.Model, instance: IssuingCa, **kwargs: Any) -> None:  # noqa: ARG001
    """Deletes the corresponding files from the filesystem when corresponding IssuingCa object is deleted.

    Args:
        instance (IssuingCa):
            The instance of the IssuingCa model.
        sender (Any):
            The sender of the signal. Must be IssuingCa model to fire.
        kwargs (Any):
            Key word arguments are required for receiver annotated functions and methods.

    Returns:
        None
    """
    if sender == IssuingCa and instance.p12:
        path = Path(instance.p12.path)
        if path.is_file():
            Path.unlink(path)


class Truststore(models.Model):
    """Truststore model."""

    class KeyType(models.TextChoices):
        """Supported key-types."""

        RSA = 'RSA', _('RSA')
        ECC = 'ECC', _('ECC')

    class Curves(models.TextChoices):
        """Supported curves."""

        SECP256R1 = 'SECP256R1', _('SECP256R1')
        SECP384R1 = 'SECP384R1', _('SECP384R1')

    common_name = models.CharField(max_length=65536, default='', blank=True)
    subject = models.CharField(max_length=65536, default='', blank=True)
    issuer = models.CharField(max_length=65536, default='', blank=True)

    not_valid_before = models.DateTimeField()
    not_valid_after = models.DateTimeField()

    key_type = models.CharField(max_length=3, choices=KeyType)
    key_size = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(65536)])
    curve = models.CharField(max_length=10, choices=Curves, default='', blank=True)

    pem = models.FileField(
        verbose_name='PEM encoded file',
    )
    created_at = models.DateTimeField(default=timezone.now)

class EndpointProfile(models.Model):
    """Endpoint Profile model."""

    unique_endpoint = models.CharField(
        max_length=100, validators=[MinLengthValidator(3), validate_isidentifer], unique=True
    )
    issuing_ca = models.ForeignKey(IssuingCa, on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self: EndpointProfile) -> str:
        """Human-readable representation of the EndpointProfile model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        if self.issuing_ca:
            return f'EndpointProfile({self.unique_endpoint}, {self.issuing_ca.unique_name})'
        return f'EndpointProfile({self.unique_endpoint}, None)'

    def save(self: EndpointProfile, *args: Any, **kwargs: Any) -> Any:
        """Save hook - transform unique_endpoint to all lower case letters

        Args:
            *args (Any): Arguments passed to the super().save() method.
            **kwargs (Any): Keyword arguments passed to the super().save() method.

        Returns:
            Any
        """
        self.unique_endpoint = self.unique_endpoint.lower()
        return super().save(*args, **kwargs)


class TestA(models.Model):
    a = models.CharField(max_length=10, default='')

    def __str__(self):
        return f'TestA({self.a})'


class TestB(models.Model):
    b = models.CharField(max_length=10, default='')
    test_a = models.ForeignKey(TestA, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return f'TestB({self.b})'


class CertificateRevocationList(models.Model):
    device_name = models.CharField(max_length=50, unique=True, help_text="Device name")
    serial_number = models.CharField(max_length=50, unique=True, help_text="Unique serial numer of revoked certificate.", primary_key=True)
    revocation_datetime = models.DateTimeField(help_text="Timestamp when certificate got revoked.")
    revocation_reason = models.CharField(max_length=255, blank=True, help_text="Reason of revoation.")
    issuer = models.ForeignKey(IssuingCa, on_delete=models.CASCADE, help_text="Name of Issuing CA.")

    def __str__(self):
        return f"{self.serial_number} - Revoked on {self.revocation_datetime.strftime('%Y-%m-%d %H:%M:%S')}"
