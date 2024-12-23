import logging

from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver

from .models import BaseCaModel
from .tasks import add_crl_to_schedule, remove_crl_from_schedule

logger = logging.getLogger('tp.pki')


@receiver(post_save, sender=BaseCaModel)
def handle_post_save(sender, instance, created, **kwargs) -> None:
    if created:
        add_crl_to_schedule(instance)


@receiver(post_delete, sender=BaseCaModel)
def handle_post_delete(sender, instance, **kwargs) -> None:
    remove_crl_from_schedule(instance)


@receiver(pre_delete, sender=BaseCaModel)
def handle_pre_delete(sender, instance, **kwargs) -> None:
    instance.issuing_ca_certificate.remove_private_key()
