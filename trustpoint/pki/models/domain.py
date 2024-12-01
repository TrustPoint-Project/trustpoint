from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from django.db import models
from django.utils.translation import gettext_lazy as _

from pki.validator.field import UniqueNameValidator
from . import TrustStoreModel, IssuingCaModel, CMPModel, ESTModel

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed448.Ed448PublicKey, ed25519.Ed25519PublicKey]


__all__ = [
    'DomainModel'
]


class DomainModel(models.Model):
    """Endpoint Profile model."""

    unique_name = models.CharField(
        _('Unique Name'),
        max_length=100,
        unique=True,
        validators=[UniqueNameValidator()])

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_('Issuing CA'),
        related_name='domain',
    )

    truststores = models.ManyToManyField(
        to=TrustStoreModel,
        verbose_name=_('Truststores'),
        related_name='domain_truststores'
    )

    def __str__(self) -> str:
        """Human-readable representation of the Domain model instance.

        Returns:
            str:
                Human-readable representation of the EndpointProfile model instance.
        """
        return self.unique_name

    def save(self, *args, **kwargs) -> None:
        self.full_clean()
        super().save(*args, **kwargs)

        # TODO: this is not save -> error handling still required. -> undo everything if something fails below
        cmp_path = '/.well-known/cmp/p/' + self.get_url_path_segment()
        CMPModel.objects.get_or_create(domain=self, url_path=cmp_path)

        est_path = '/.well-known/est/' + self.get_url_path_segment()
        ESTModel.objects.get_or_create(domain=self, url_path=est_path)


    def get_url_path_segment(self):
        """@BytesWelder: I don't know what we need this for. @Alex mentioned this in his doc.

        Returns:
            str:
                URL path segment.
        """
        return self.unique_name.lower().replace(' ', '-')

    def get_protocol_object(self, protocol):
        """Get corresponding CMP object"""
        if protocol == 'cmp':
            return self.cmp_protocol
        if protocol == 'est':
            return self.est_protocol
        # msg = f'Unknown protocol: {protocol}.'
        # raise ValueError(msg)