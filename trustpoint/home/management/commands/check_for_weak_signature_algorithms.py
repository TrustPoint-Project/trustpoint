"""Management command to check for weak signature algorithms."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand  # type: ignore[import-untyped]
from django.utils import timezone  # type: ignore[import-untyped]
from home.models import NotificationModel, NotificationStatus
from pki.models import CertificateModel


class Command(BaseCommand):
    """Custom Django management command to check certificates for weak signature algorithms."""

    help = 'Check certificates with weak or deprecated signature algorithms.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command."""
        self._check_for_weak_signature_algorithms()
        self.stdout.write(self.style.SUCCESS('Weak signature algorithms check completed.'))

    def _check_for_weak_signature_algorithms(self) -> None:
        """Task to check if any certificates are using weak or deprecated signature algorithms."""
        weak_algorithms = ['1.2.840.113549.2.5', '1.3.14.3.2.26']  # OIDs for MD5 and SHA-1

        weak_certificates = CertificateModel.objects.filter(signature_algorithm_oid__in=weak_algorithms)
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for cert in weak_certificates:
            if not NotificationModel.objects.filter(event='WEAK_SIGNATURE_ALGORITHM', certificate=cert).exists():
                message_data = {'common_name': cert.common_name, 'signature_algorithm': cert.signature_algorithm}

                notification = NotificationModel.objects.create(
                    certificate=cert,
                    created_at=timezone.now(),
                    event='WEAK_SIGNATURE_ALGORITHM',
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.WEAK_SIGNATURE_ALGORITHM,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
