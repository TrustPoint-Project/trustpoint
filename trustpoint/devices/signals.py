from devices.models import Device
from pki.models import Certificate
from django.db.models.signals import pre_delete
from django.dispatch import receiver


@receiver([pre_delete], sender=Device)
def device_pre_delete(sender, instance, **kwargs):
    """Revoke certificate on device deletion."""
    if instance.ldevid:
        instance.revoke_ldevid()
