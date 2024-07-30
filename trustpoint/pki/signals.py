from .models import CertificateModel, KeyUsageExtension, BasicConstraintsExtension, IssuingCaModel
from django.db.models.signals import pre_delete
import logging

from django.db.backends.signals import connection_created
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import BasicConstraintsExtension, CertificateModel, DomainModel, IssuingCaModel, KeyUsageExtension
from .tasks import add_crl_to_schedule, remove_crl_from_schedule

log = logging.getLogger('tp.pki')

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
        log.warning(
            'Issuing CA certificate %s remains in DB as it has issued certificates.', instance.issuing_ca_certificate)


@receiver(post_save, sender=IssuingCaModel)
@receiver(post_save, sender=DomainModel)
def handle_post_save(sender, instance, created, **kwargs) -> None:
    if created:
        add_crl_to_schedule(instance)


@receiver(post_delete, sender=IssuingCaModel)
@receiver(post_delete, sender=DomainModel)
def handle_post_delete(sender, instance, **kwargs) -> None:
    remove_crl_from_schedule(instance)

crl_thread_started = False

@receiver(connection_created)
def initial_database_connection(sender, connection, **kwargs):
    global crl_thread_started
    if crl_thread_started:
        return
    crl_thread_started = True

    log.info('Initial database connection established: %s', connection.alias)

    from .tasks import start_crl_generation_thread
    start_crl_generation_thread()