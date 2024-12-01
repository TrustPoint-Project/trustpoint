from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _
from .certificate import CertificateModel
from core.serializer import CertificateCollectionSerializer
from core.validator.field import UniqueNameValidator


__all__ = [
    'TrustStoreModel',
    'TrustStoreOrderModel',
    'TrustpointTlsServerCredentialModel',
    'ActiveTrustpointTlsServerCredentialModel'
]


class TrustStoreModel(models.Model):

    unique_name = models.CharField(
        verbose_name=_('Unique Name'),
        max_length=100,
        validators=[UniqueNameValidator()],
        unique=True
    )

    certificates = models.ManyToManyField(
        to=CertificateModel,
        verbose_name=_('Intermediate CA Certificates'),
        through='TrustStoreOrderModel')

    @property
    def number_of_certificates(self) -> int:
        return len(self.certificates.all())

    def __str__(self) -> str:
        return self.unique_name

    def get_serializer(self) -> CertificateCollectionSerializer:
        return CertificateCollectionSerializer(
            [cert_model.get_certificate_serializer() for cert_model in self.certificates.all()]
        )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class TrustStoreOrderModel(models.Model):

    class Meta:
        unique_together = ('order', 'trust_store')

    order = models.PositiveSmallIntegerField(verbose_name=_('Trust Store Certificate Index (Order)'), editable=False)
    certificate = models.ForeignKey(
        CertificateModel,
        on_delete=models.CASCADE,
        editable=False,
        related_name='trust_store_components')
    trust_store = models.ForeignKey(TrustStoreModel, on_delete=models.CASCADE, editable=False)


class TrustpointTlsServerCredentialModel(models.Model):
    private_key_pem = models.CharField(verbose_name=_('Private Key (PEM)'), max_length=65536, editable=False)
    certificate = models.ForeignKey(CertificateModel, on_delete=models.CASCADE)
    trust_store = models.ForeignKey(TrustStoreModel, on_delete=models.CASCADE)


class ActiveTrustpointTlsServerCredentialModel(models.Model):
    credential = models.ForeignKey(
        TrustpointTlsServerCredentialModel,
        on_delete=models.CASCADE,
        blank=True,
        null=True
    )

    def save(self, *args, **kwargs):
        self.id = 1
        super().save(*args, **kwargs)
