"""Defines signal handlers for the devices app.

This module includes signal handlers for Device model events, such as
revoking certificates before a device is deleted.
"""
from __future__ import annotations

from django.db.models.signals import pre_delete
from django.dispatch import receiver
from pki import ReasonCode
from pki.models import DomainModel

from devices.models import Device


@receiver([pre_delete], sender=Device)
def device_pre_delete(sender: type[Device], instance: Device, **_: dict) -> None: # noqa: ARG001
    """Revoke certificate on device deletion.

    Args:
        sender (type[Device]): The model class that sent the signal.
        instance (Device): The instance of the model being deleted.
        **_ (dict): Additional keyword arguments provided by the signal.
    """
    if isinstance(instance.domain, DomainModel) and instance.get_current_ldevid_by_domain(domain=instance.domain):
        instance.revoke_ldevid(revocation_reason=ReasonCode.CESSATION)
