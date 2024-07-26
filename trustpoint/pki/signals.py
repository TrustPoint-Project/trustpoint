from .models import CertificateModel, KeyUsageExtension, BasicConstraintsExtension, IssuingCaModel
from django.db.models.signals import pre_delete
from django.dispatch import receiver


# TODO:
# @receiver([post_delete], sender=Certificate)
# def update_delete_student(sender, instance, **kwargs):
#     BasicConstraintsExtension.objects.filter(certificates__isnull=True).delete()
#     KeyUsageExtension.objects.filter(certificates__isnull=True).delete()


@receiver([pre_delete], sender=IssuingCaModel)
def update_delete_student(sender, instance, **kwargs):
    # RuntimeError is raised if the issuing ca certificate has other references pointing to it.
    # Hence, it will not be deleted in this case.
    print(instance.issuing_ca_certificate)
    print(instance.issuing_ca_certificate)
    print(instance.root_ca_certificate)
    try:
        instance.issuing_ca_certificate.delete()
    except RuntimeError:
        pass
