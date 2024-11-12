from django.db.models.signals import pre_delete
from django.dispatch import receiver
from pki import ReasonCode

from devices.models import Device


@receiver([pre_delete], sender=Device)
def device_pre_delete(sender, instance, **kwargs):
    """Revoke certificate on device deletion."""
    if instance.get_current_ldevid_by_domain(domain=instance.domain):
        instance.revoke_ldevid(revocation_reason=ReasonCode.CESSATION)
