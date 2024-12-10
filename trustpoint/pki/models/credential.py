"""Module that contains the CredentialModel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import QuerySet

from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)
from django.core.exceptions import ValidationError  # type: ignore[import-untyped]
from django.db import models, transaction  # type: ignore[import-untyped]
from django.utils.translation import gettext_lazy as _  # type: ignore[import-untyped]
from core.x509 import CredentialNormalizer
from pki.models import CertificateModel

if TYPE_CHECKING:
    from typing import Any, ClassVar, Union

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    PrivateKey = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey]


__all__ = ['CredentialAlreadyExistsError', 'CredentialModel', 'CertificateChainOrderModel']


class CredentialAlreadyExistsError(ValidationError):

    def __init__(self, *args: tuple, **kwargs: dict) -> None:
        super().__init__(message=_('Credential already exists.'), *args, **kwargs)


class CredentialModel(models.Model):
    """The CredentialModel that holds all local credentials used by the Trustpoint.

    This model holds both local unprotected credentials, for which the keys and certificates are stored
    in the DB, but also credentials that are stored within an HSM or TPM utilizing PKCS#11.

    PKCS#11 credentials are not yet supported.
    """

    class Meta:
        """Metaclass configurations."""
        constraints = [
            models.UniqueConstraint(fields=['certificate'], name='unique_certificate'),
        ]

    class CredentialTypeChoice(models.IntegerChoices):
        """The CredentialTypeChoice defines the type of the credential and thus implicitly restricts its usage.

        It is intended to limit the credential usage to specific cases, e.g. usage as Issuing CA.
        The abstractions using the CredentialModel are responsible to check that the credential has
        the correct and expected CredentialTypeChoice.
        """

        TRUSTPOINT_TLS_SERVER = 0, _('Trustpoint TLS Server')
        ROOT_CA = 1, _('Root CA')
        ISSUING_CA = 2, _('Issuing CA')
        ISSUED_DOMAIN_CREDENTIAL_WITH_KEY = 3, _('Issued Domain Credential')
        ISSUED_DOMAIN_CREDENTIAL_WITHOUT_KEY = 4, _('Issued Domain Credential')

    credential_type = models.IntegerField(
        verbose_name=_('Credential Type'), choices=CredentialTypeChoice
    )
    private_key = models.CharField(verbose_name='Private key (PEM)', max_length=65536, editable=False)

    certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.PROTECT,
        editable=False,
        blank=False,
        null=False,
        related_name='credentials'
    )
    certificate_chain = models.ManyToManyField(
        CertificateModel,
        blank=True,
        through='CertificateChainOrderModel',
        related_name='credential_certificate_chains'
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __repr__(self) -> str:
        return (
            f'CredentialModel(credential_type={self.credential_type}, '
            f'certificate={self.certificate})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return self.__repr__()

    def save(self, *args: tuple, **kwargs: dict) -> None:
        if self.pk:
            err_msg = _('Editing existing credentials is not supported.')
            raise ValidationError(err_msg)
        if CredentialModel.objects.filter(certificate=self.certificate).exists():
            raise CredentialAlreadyExistsError()
        super().save(*args, **kwargs)

    @classmethod
    def save_credential_serializer(
            cls, credential_serializer: CredentialSerializer,
            credential_type: CredentialModel.CredentialTypeChoice
    ) -> CredentialModel:
        """This method will try to normalize the credential_serializer and then save it to the database.

        Args:
            credential_serializer: The credential serializer to store in the database.
            credential_type: The credential type to set.

        Returns:
            CredentialModel: The stored credential model.
        """
        normalized_credential_serializer = CredentialNormalizer(credential_serializer).normalized_credential
        return cls._save_normalized_credential_serializer(
            normalized_credential_serializer=normalized_credential_serializer,
            credential_type=credential_type
        )

    @property
    def ordered_certificate_chain_queryset(self) -> QuerySet:
        return self.certificatechainordermodel_set.order_by('order')

    @classmethod
    @transaction.atomic
    def _save_normalized_credential_serializer(
            cls,
            normalized_credential_serializer: CredentialSerializer,
            credential_type: CredentialModel.CredentialTypeChoice
    ) -> CredentialModel:
        """This method will store a credential that is expected to be normalized..

        Args:
            normalized_credential_serializer: The normalized credential serializer to store in the database.

        Returns:
            CredentialModel: The stored credential model.
        """

        certificate = CertificateModel.save_certificate(
            normalized_credential_serializer.credential_certificate
        )
        # TODO(AlexHx8472): Verify that the credential is valid in respect to the credential_type!!!

        credential_model = cls.objects.create(
            credential_type=credential_type,
            private_key=normalized_credential_serializer.credential_private_key.as_pkcs8_pem().decode(),
            certificate=certificate
        )

        for order, certificate in enumerate(normalized_credential_serializer.additional_certificates.as_crypto()):
            certificate_model = CertificateModel.save_certificate(certificate)
            CertificateChainOrderModel.objects.create(
                certificate=certificate_model, credential=credential_model, order=order
            )

        return credential_model

    # TODO(AlexHx8472): Implement the delete method,
    # TODO(AlexHx8472): so that the corresponding CertificateChainOrderModels are removed as well

    def get_private_key(self) -> PrivateKey:
        """Gets an abstraction of the credential private key.

        Note, in the case of keys stored in an HSM or TPM using PKCS#11, it will only be possible to use the
        key abstraction to sign and verify, but not to export the key in any way.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer(self.private_key).as_crypto()

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_private_key_serializer(self) -> PrivateKeySerializer:
        """Gets a serializer of the credential private key.

        Returns:
            PrivateKey: The credential private key abstraction.
        """
        if self.private_key:
            return PrivateKeySerializer(self.private_key)

        err_msg = 'Failed to get private key information.'
        raise RuntimeError(err_msg)

    def get_certificate(self) -> x509.Certificate:
        """Gets the credential certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The credential certificate.
        """
        return self.get_certificate_serializer().as_crypto()

    def get_certificate_chain(self) -> list[x509.Certificate]:
        """Gets the credential certificate chain as list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: The credential certificate chain as list of x509.Certificate instances.
        """
        return self.get_certificate_chain_serializer().as_crypto()

    def get_certificate_serializer(self) -> CertificateSerializer:
        """Gets the credential certificate as CertificateSerializer instance.

        Returns:
            CertificateSerializer: The credential certificate.
        """
        return self.certificate.get_certificate_serializer()

    def get_certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        """Gets the credential certificate chain as CertificateCollectionSerializer instance.

        Returns:
            CertificateCollectionSerializer: The credential certificate chain.
        """
        certificate_chain_order_models = self.certificatechainordermodel_set.order_by('order')
        return CertificateCollectionSerializer(
            [
                certificate_chain_order_model.certificate.get_certificate_serializer()
                for certificate_chain_order_model in certificate_chain_order_models
            ],
        )


class CertificateChainOrderModel(models.Model):
    """This Model is used to preserve the order of certificates in credential certificate chains."""

    certificate = models.ForeignKey(CertificateModel, on_delete=models.PROTECT, null=False, blank=False, editable=False)
    credential = models.ForeignKey(CredentialModel, on_delete=models.PROTECT, null=False, blank=False, editable=False)
    order = models.PositiveIntegerField(null=False, blank=False, editable=False)

    class Meta:
        """This Meta class add some configuration to the CertificateChainOrderModel.

        Sets the default ordering such that the field order is used.
        Restricts entries such that the tuple (credential, order) is unique.
        """

        ordering: ClassVar = ['order']
        constraints: ClassVar = [models.UniqueConstraint(fields=['credential', 'order'], name='unique_group_order')]

    def __repr__(self) -> str:
        return (
            f'CertificateChainOrderModel(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'order={self.order})'
        )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return self.__repr__()

    # TODO(AlexHx8472): Validate certificate chain!
    def save(self, *args: tuple[Any], **kwargs: dict[str, Any]) -> None:
        """Stores a CertificateChainOrderModel in the database.

        This is only possible if the order takes the next available value. That is, e.g. if the corresponding
        credential certificate chain has already two certificates stored with order 0 and 1, then the next
        entry to be stored must have order 2.

        Args:
            *args: Positional arguments, passed to super().save()
            **kwargs: Keyword arguments, passed to super().save()

        Returns:
            None

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry to be stored does not have the correct order.
        """
        max_order = self._get_max_order()

        if self.order != max_order + 1:
            err_msg = f'Cannot add Membership with order {self.order}. Expected {max_order + 1}.'
            raise ValidationError(err_msg)
        super().save(*args, **kwargs)

    def delete(self, *args: tuple[Any], **kwargs: dict[str, Any]) -> None:
        """Tries to delete the CertificateChainOrderModel entry.

        A CertificateChainOrderModel entry can only be deleted if it has the highest order in the
        corresponding credential certificate chain.

        Args:
            *args: Positional arguments, passed to super().delete()
            **kwargs: Keyword arguments, passed to super().delete()

        Returns:
            None

        Raises:
            ValueError:
                If the CertificateChainOrderModel entry does not have the highest order in the corresponding
                credential certificate chain.
        """
        max_order = self._get_max_order()

        if self.order != max_order:
            err_msg = (
                f'Only the Membership with the highest order ({max_order}) '
                f'can be deleted. This Membership has order {self.order}.'
            )
            raise ValidationError(err_msg)

        super().delete(*args, **kwargs)

    def _get_max_order(self) -> int:
        """Gets highest order of a certificate of a credential certificate chain.

        Returns:
            int: The highest order of a certificate of a credential certificate chain.
        """
        existing_orders = CertificateChainOrderModel.objects.filter(credential=self.credential).values_list(
            'order', flat=True
        )
        return max(existing_orders, default=-1)
