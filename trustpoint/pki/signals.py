from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import BasicConstraintsExtension, Certificate, DomainProfile, IssuingCa, KeyUsageExtension
from .tasks import add_crl_to_schedule, remove_crl_from_schedule

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


@receiver(post_save, sender=IssuingCa)
@receiver(post_save, sender=DomainProfile)
def handle_post_save(sender, instance, created, **kwargs) -> None:
    if created:
        add_crl_to_schedule(instance)

@receiver(post_delete, sender=IssuingCa)
@receiver(post_delete, sender=DomainProfile)
def handle_post_delete(sender, instance, **kwargs) -> None:
    remove_crl_from_schedule(instance)
