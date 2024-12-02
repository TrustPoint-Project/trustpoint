"""Django Models that hold and store X.509 Credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)
from core.util.x509 import CredentialNormalizer
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from pki.models import CertificateModel

if TYPE_CHECKING:
    from typing import Any, ClassVar, Union

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    PrivateKey = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]


__all__ = ['CredentialModel']


class CredentialModel(models.Model):
    """The CredentialModel that holds all local credentials used by the Trustpoint.

    This model holds both local unprotected credentials, for which the keys and certificates are stored
    in the DB, but also credentials that are stored within a HSM or TPM utilizing PKCS#11.

    PKCS#11 credentials are not yet supported.
    """

    class CredentialAllowedUsageChoice(models.IntegerChoices):
        """The CredentialAllowedUsageChoice defines the allowed usage of the credential.

        It is intended to limit the credential usage to specific cases, e.g. usage as Issuing CA.
        The abstractions using the CredentialModel are responsible to check that the credential has
        the correct and expected CredentialAllowedUsageChoice.
        """

        TRUSTPOINT_TLS_SERVER = 0, _('Trustpoint TLS Server')
        ROOT_CA = 1, _('Root CA')
        ISSUING_CA = 2, _('Issuing CA')

    credential_allowed_usage = models.IntegerField(
        verbose_name=_('Credential Allowed Usages'), choices=CredentialAllowedUsageChoice
    )
    private_key = models.CharField(verbose_name='Private key (PEM)', max_length=65536, editable=False)
    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.CASCADE, editable=False, blank=False, null=False, related_name='credentials'
    )
    certificate_chain = models.ManyToManyField(
        CertificateModel, blank=True, through='CertificateChainOrderModel', related_name='credential_certificate_chains'
    )

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return (
            f'CredentialModel(credential_allowed_usage={self.credential_allowed_usage}, '
            f'certificate={self.certificate})'
        )

    def save(self, *_: tuple[Any], **__: dict[str, Any]) -> None:
        """Overwrites the save method such that always a NotImplementedError will be raised.

        Use the save_credential_serializer() method to store credentials.

        Returns:
            None

        Raises:
            NotImplementedError: Will always be raised.
        """
        err_msg = 'You cannot save credentials directly. Use the save_credential_serializer() method.'
        raise NotImplementedError(err_msg)

    @classmethod
    def save_credential_serializer(cls, credential_serializer: CredentialSerializer) -> CredentialModel:
        """This method will try to normalize the credential_serializer and then save it to the database.

        Args:
            credential_serializer: The credential serializer to store in the database.

        Returns:
            CredentialModel: The stored credential model.
        """
        normalized_credential = CredentialNormalizer(credential_serializer).normalized_credential
        return cls._save_normalized_credential_serializer(normalized_credential)

    @classmethod
    @transaction.atomic
    def _save_normalized_credential_serializer(
        cls, normalized_credential_serializer: CredentialSerializer
    ) -> CredentialModel:
        """This method will store a credential that is expected to be normalized..

        Args:
            normalized_credential_serializer: The normalized credential serializer to store in the database.

        Returns:
            CredentialModel: The stored credential model.
        """
        credential_model = cls.objects.create(
            private_key=normalized_credential_serializer.credential_private_key.as_pkcs8_pem().decode(),
            certifciate=normalized_credential_serializer.credential_certificate.as_pem().decode(),
        )

        for order, certificate in enumerate(normalized_credential_serializer.additional_certificates.as_crypto()):
            certificate_model = CertificateModel.save_certificate(certificate, exist_ok=True)
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

    certificate = models.ForeignKey(CertificateModel, on_delete=models.CASCADE, null=False, blank=False, editable=False)
    credential = models.ForeignKey(CredentialModel, on_delete=models.CASCADE, null=False, blank=False, editable=False)
    order = models.PositiveIntegerField(null=False, blank=False, editable=False)

    class Meta:
        """This Meta class add some configuration to the CertificateChainOrderModel.

        Sets the default ordering such that the field order is used.
        Restricts entries such that the tuple (credential, order) is unique.
        """

        ordering: ClassVar = ['order']
        constraints: ClassVar = [models.UniqueConstraint(fields=['credential', 'order'], name='unique_group_order')]

    def __str__(self) -> str:
        """Returns a human-readable string that represents this CertificateChainOrderModel entry.

        Returns:
            str: Human-readable string that represents this CertificateChainOrderModel entry.
        """
        return (
            f'CertificateChainOrderModel(credential={self.credential}, '
            f'certificate={self.certificate}, '
            f'order={self.order})'
        )

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
        max_order = self.get_max_order()

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
        max_order = self.get_max_order()

        if self.order != max_order:
            err_msg = (
                f'Only the Membership with the highest order ({max_order}) '
                f'can be deleted. This Membership has order {self.order}.'
            )
            raise ValidationError(err_msg)

        super().delete(*args, **kwargs)

    def get_max_order(self) -> int:
        """Gets highest order of a certificate of a credential certificate chain.

        Returns:
            int: The highest order of a certificate of a credential certificate chain.
        """
        existing_orders = CertificateChainOrderModel.objects.filter(credential=self.credential).values_list(
            'order', flat=True
        )
        return max(existing_orders, default=-1)
