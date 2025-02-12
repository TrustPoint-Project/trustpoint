"""Module that contains the DomainModel."""
from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.validator.field import UniqueNameValidator
from . import IssuingCaModel

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


__all__ = [
    'DomainModel'
]


class DomainModel(models.Model):
    """Domain Model."""

    unique_name = models.CharField(
        _('Domain Name'),
        max_length=100,
        unique=True,
        validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_('Issuing CA'),
        related_name='domains',
    )

    auto_create_new_device = models.BooleanField(
        _('Auto-create New Device'),
        default=False,
        help_text=_(
            "Automatically create a new device if no device with the same serial number exists in the database."
        )
    )

    allow_username_password_registration = models.BooleanField(
        _('Allow username:password Registration'),
        default=False,
        help_text=_("New devices can be added with a username and password.")
    )

    allow_idevid_registration = models.BooleanField(
        _('Allow IDevID Registration'),
        default=False,
        help_text=_("Allow registration of a new device using the IDevID of the Device.")
    )

    domain_credential_auth = models.BooleanField(
        _('Require a Domain Credential for Authentication'),
        default=True,
        help_text=_("The EST server requires a domain credential issued by the domain Issuing CA for authenitcation.")
    )

    username_password_auth = models.BooleanField(
        _('Require username:password for Authentication'),
        default=False,
        help_text=_("The EST server requires username and password for authentication.")
    )

    allow_app_certs_without_domain = models.BooleanField(
        _('Allow Application Certificates without Domain Credential'),
        default=False,
        help_text=_("Allow issuance of application certificates without a domain credential.")
    )

    def __repr(self) -> str:
        return f'DomainModel(unique_name={self.unique_name})'

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        return self.unique_name


