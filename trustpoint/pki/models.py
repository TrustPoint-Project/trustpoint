from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, MinValueValidator, MaxValueValidator
from trustpoint.validators import validate_isidentifer
from django.dispatch import receiver
from pathlib import Path
import os


class IssuingCa(models.Model):
    class KeyType(models.TextChoices):
        RSA = 'RSA', _('RSA')
        ECC = 'ECC', _('ECC')

    class Curves(models.TextChoices):
        SECP256R1 = 'SECP256R1', _('SECP256R1')
        SECP384R1 = 'SECP384R1', _('SECP384R1')

    class Localization(models.TextChoices):
        L = 'L', _('Local')
        R = 'R', _('Remote')

    class ConfigType(models.TextChoices):
        F_P12 = 'F_P12', _('File Import - PKCS#12')
        F_PEM = 'F_PEM', _('File Import - PEM')

    unique_name = models.CharField(
        max_length=100, validators=[MinLengthValidator(6), validate_isidentifer], unique=True
    )

    common_name = models.CharField(max_length=65536, null=True, blank=True)
    root_common_name = models.CharField(max_length=65536, null=True, blank=True)
    not_valid_before = models.DateTimeField()
    not_valid_after = models.DateTimeField()

    key_type = models.CharField(max_length=3, choices=KeyType)
    key_size = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(65536)])
    curve = models.CharField(max_length=10, choices=Curves, null=True, blank=True, default=None)
    localization = models.CharField(max_length=1, choices=Localization)
    config_type = models.CharField('Configuration Type', max_length=10, choices=ConfigType)

    p12 = models.FileField(verbose_name='PKCS#12 File (.p12, .pfx)', )
    created_at = models.DateTimeField(default=timezone.now)

    def get_delete_url(self):
        return f'delete/{self.pk}/'

    def get_details_url(self):
        return f'details/{self.pk}/'

    def __str__(self) -> str:
        return f'IssuingCa({self.unique_name}, {self.localization})'


@receiver(models.signals.post_delete, sender=IssuingCa)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """Deletes file from filesystem when corresponding `IssuingCa` object is deleted."""
    if instance.p12:
        path = Path(instance.p12.path)
        if path.is_file():
            os.remove(path)


@receiver(models.signals.pre_save, sender=IssuingCa)
def auto_delete_file_on_change(sender, instance, **kwargs):
    """Deletes old file from filesystem when corresponding `IssuingCa` object is updated with new file."""
    if not instance.pk:
        return False
