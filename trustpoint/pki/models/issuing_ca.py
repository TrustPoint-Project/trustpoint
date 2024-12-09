"""Module that contains the IssuingCaModel."""
from __future__ import annotations

from django.db import models  # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]

from pki.models.credential import CredentialModel
from trustpoint.views.base import LoggerMixin
from core.validator.field import UniqueNameValidator
from core.serializer import CredentialSerializer


class IssuingCaModel(LoggerMixin, models.Model):
    """Issuing CA Model.

    This model contains the configurations of all Issuing CAs available within the Trustpoint.
    """

    class IssuingCaTypeChoice(models.IntegerChoices):
        """The IssuingCaTypeChoice defines the type of Issuing CA.

        Depending on the type other fields may be set, e.g. a credential will only be available for local
        Issuing CAs.
        """
        AUTOGEN = 0, _('Auto-Generated')
        LOCAL_UNPROTECTED = 1, _('Local-Unprotected')
        LOCAL_PKCS11 = 2, _('Local-PKCS11')
        REMOTE_EST = 3, _('Remote-EST')
        REMOTE_CMP = 4, _('Remote-CMP')

    unique_name = models.CharField(
        verbose_name=_('Issuing CA Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True)
    credential = models.OneToOneField(CredentialModel, related_name='issuing_cas', on_delete=models.PROTECT)
    issuing_ca_type = models.IntegerField(verbose_name=_('Issuing CA Type'), choices=IssuingCaTypeChoice, null=False, blank=False)

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)
    updated_at = models.DateTimeField(verbose_name=_('Updated'), auto_now=True)

    def __repr__(self) -> str:
        return f'IssuingCaModel(unique_name={self.unique_name})'

    def __str__(self) -> str:
        """Returns a human-readable string that represents this IssuingCaModel entry.

        Returns:
            str: Human-readable string that represents this IssuingCaModel entry.
        """
        return self.unique_name

    @classmethod
    @LoggerMixin.log_exceptions
    def create_new_issuing_ca(
            cls,
            unique_name: str,
            credential_serializer: CredentialSerializer,
            issuing_ca_type: IssuingCaModel.IssuingCaTypeChoice) -> IssuingCaModel:
        """Creates a new Issuing CA model and returns it.

        Args:
            unique_name: The unique name that will be used to identify the Issuing CA.
            credential_serializer:
                The credential as CredentialSerializer instance.
                It will be normalized and validated, if it is a valid credential to be used as an Issuing CA.
            issuing_ca_type: The Issuing CA type.

        Returns:
            IssuingCaModel: The newly created Issuing CA model.
        """
        issuing_ca_types = (
            cls.IssuingCaTypeChoice.AUTOGEN,
            cls.IssuingCaTypeChoice.LOCAL_UNPROTECTED,
            cls.IssuingCaTypeChoice.LOCAL_PKCS11
        )
        if issuing_ca_type in issuing_ca_types:
            credential_type = CredentialModel.CredentialTypeChoice.ISSUING_CA
        else:
            raise ValueError(f'Issuing CA Type {issuing_ca_type} is not yet supported.')

        credential_model = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer,
            credential_type=credential_type
        )

        issuing_ca = cls(
            unique_name=unique_name,
            credential=credential_model,
            issuing_ca_type=issuing_ca_type,
        )
        issuing_ca.save()
        return issuing_ca
