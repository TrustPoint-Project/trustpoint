from django.db import models
from trustpoint.settings import BASE_DIR
from pathlib import Path
from django.utils import timezone


class LocalIssuingCa(models.Model):
    p12 = models.FileField(verbose_name='PKCS#12 File (.p12, .pfx)')
    p12_password = models.CharField(max_length=100, verbose_name='PKCS#12 Password', default=None, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f'LocalIssuingCa({self.p12.name})'


class IssuingCa(models.Model):
    unique_name = models.CharField(max_length=100)
    local_issuing_ca = models.OneToOneField(
        LocalIssuingCa,
        on_delete=models.CASCADE,
        primary_key=True
    )

    def __str__(self) -> str:
        return f'IssuingCa({self.unique_name}, {self.local_issuing_ca})'
