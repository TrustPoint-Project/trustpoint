from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinLengthValidator, MinValueValidator, MaxValueValidator
from trustpoint.validators import validate_isidentifer


class LocalIssuingCa(models.Model):
    p12 = models.FileField(verbose_name='PKCS#12 File (.p12, .pfx)')
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f'LocalIssuingCa({self.p12.name})'


class IssuingCa(models.Model):

    class KeyType(models.TextChoices):
        RSA = 'RSA', _('RSA')
        ECC = 'ECC', _('ECC')

    class Curves(models.TextChoices):
        SECP256R1 = 'SECP256R1', _('SECP256R1')
        SECP384R1 = 'SECP384R1', _('SECP384R1')

    unique_name = models.CharField(
        max_length=100, validators=[MinLengthValidator(6), validate_isidentifer], unique=True)

    # since the certificate is not an EE but an CA certificate, the subject must not be None
    subject = models.CharField(max_length=1024)
    issuer = models.CharField(max_length=1024)
    not_valid_before = models.DateTimeField()
    not_valid_after = models.DateTimeField()

    root_subject = models.CharField(max_length=1024)
    chain_not_valid_before = models.DateTimeField()
    chain_not_valid_after = models.DateTimeField()

    key_type = models.CharField(max_length=3, choices=KeyType)
    key_size = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(65536)])
    curve = models.CharField(max_length=10, choices=Curves, null=True, blank=True, default=None)

    local_issuing_ca = models.OneToOneField(
        LocalIssuingCa,
        on_delete=models.CASCADE,
        primary_key=True
    )

    def __str__(self) -> str:
        return f'IssuingCa({self.unique_name}, {self.local_issuing_ca})'
