"""Module that contains all models corresponding to the PKI application."""


from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from django.db import models
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from trustpoint.validators import validate_isidentifer


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

    unique_name = models.CharField(
        max_length=100, validators=[MinLengthValidator(3), validate_isidentifer], unique=True
    )

    common_name = models.CharField(max_length=65536, default='', blank=True)
    root_common_name = models.CharField(max_length=65536, default='', blank=True)
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


# noinspection PyUnusedLocal
@receiver(models.signals.post_delete)
def auto_delete_file_on_delete(sender: models.Model, instance: IssuingCa, **kwargs: Any) -> None:   # noqa: ARG001
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
        self.unique_endpoint = self.unique_endpoint.lower()
        return super().save(*args, **kwargs)
