from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _
from .certificate import CertificateModel


__all__ = [
    'TrustpointTlsServerCredentialModel',
    'ActiveTrustpointTlsServerCredentialModel'
]



class TrustpointTlsServerCredentialModel(models.Model):
    private_key_pem = models.CharField(verbose_name=_('Private Key (PEM)'), max_length=65536, editable=False)
    certificate = models.ForeignKey(CertificateModel, on_delete=models.CASCADE)


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
