import logging

from django.db.backends.signals import connection_created
from django.db.models.signals import post_delete, post_save, pre_delete
from django.dispatch import receiver

from pki.pki.request.message import Protocols

from .models import DomainModel, BaseCaModel, CMPModel, ESTModel
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
    print(sender)
    instance.issuing_ca_certificate.remove_private_key()


crl_thread_started = False


@receiver(connection_created)
def initial_database_connection(sender, connection, **kwargs):
    global crl_thread_started
    if crl_thread_started:
        return
    crl_thread_started = True

    logger.info('Initial database connection established: %s', connection.alias)


@receiver(post_save, sender=DomainModel)
def initialize_protocol_statuses(sender, instance, created, **kwargs):
    """Signal to initialize protocol statuses after a domain is created."""
    if created:
        cmp_path = '/.well-known/cmp/p/' + instance.get_url_path_segment()
        CMPModel.objects.get_or_create(domain=instance, url_path=cmp_path)

        est_path = '/.well-known/est/' + instance.get_url_path_segment()
        ESTModel.objects.get_or_create(domain=instance, url_path=est_path)
