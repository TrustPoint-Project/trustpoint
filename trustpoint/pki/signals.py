from .models import Certificate, KeyUsageExtension, BasicConstraintsExtension, IssuingCa
from django.db.models.signals import post_delete
from django.dispatch import receiver


# TODO:
# @receiver([post_delete], sender=Certificate)
# def update_delete_student(sender, instance, **kwargs):
#     BasicConstraintsExtension.objects.filter(certificates__isnull=True).delete()
#     KeyUsageExtension.objects.filter(certificates__isnull=True).delete()


@receiver([post_delete], sender=IssuingCa)
def update_delete_student(sender, instance, **kwargs):
    # RuntimeError is raised if the issuing ca certificate has other references pointing to it.
    # Hence, it will not be deleted in this case.
    try:
        instance.issuing_ca_certificate.delete()
    except RuntimeError:
        pass
