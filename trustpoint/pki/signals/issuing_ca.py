"""Signals sent by the IssuingCaModel."""

from __future__ import annotations

from django.db.models.signals import post_delete, pre_delete  # type: ignore[import-untyped]
from django.dispatch import receiver  # type: ignore[import-untyped]

from pki.models.credential import CertificateChainOrderModel
from pki.models.issuing_ca import IssuingCaModel

__all__ = ['delete_related_credential_certificate_chain_order_records', 'delete_related_credential_record']


@receiver(pre_delete, sender=IssuingCaModel)
def delete_related_credential_certificate_chain_order_records(
    sender: type[IssuingCaModel],  # noqa: ARG001
    instance: IssuingCaModel,
    **kwargs: dict,  # noqa: ARG001
) -> None:
    """Deletes the related issuing ca credential certificate chain records.

    Does not delete the certificates itself, just the chain consisting of references.

    Args:
        sender: The class of the IssuingCaModel.
        instance: The instance of the IssuingCaModel.
        **kwargs: Keyword arguments.

    Returns:
        None
    """
    CertificateChainOrderModel.objects.filter(credential=instance.credential).delete()


@receiver(post_delete, sender=IssuingCaModel)
def delete_related_credential_record(
    sender: type[IssuingCaModel],  # noqa: ARG001
    instance: IssuingCaModel,
    **kwargs: dict,  # noqa: ARG001
) -> None:
    """Deletes the related issuing ca credential record.

    Args:
        sender: The class of the IssuingCaModel.
        instance: The instance of the IssuingCaModel.
        **kwargs: Keyword arguments.

    Returns:
        None
    """
    instance.credential.delete()
