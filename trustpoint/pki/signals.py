from .models import Certificate, KeyUsageExtension, BasicConstraintsExtension
from django.db.models.signals import post_delete
from django.dispatch import receiver


@receiver([post_delete], sender=Certificate)
def update_delete_student(sender, instance, **kwargs):
    # IssuerAlternativeNameExtension.objects.filter(certificates__isnull=True).delete()
    BasicConstraintsExtension.objects.filter(certificates__isnull=True).delete()
    KeyUsageExtension.objects.filter(certificates__isnull=True).delete()
