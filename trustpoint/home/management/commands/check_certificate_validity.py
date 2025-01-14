"""Management command to check the validity of certificates.

This module defines a Django management command that checks for expiring
or expired certificates stored in the database. Expiring certificates
trigger a WARNING notification, while expired certificates trigger a
CRITICAL notification. Notifications are created only if they do not
already exist for the given certificate and event.
"""
from __future__ import annotations

from typing import Any, cast
from datetime import timedelta

from django.core.management.base import BaseCommand  # type: ignore[import-untyped]
from django.utils import timezone  # type: ignore[import-untyped]
from home.models import NotificationModel, NotificationStatus
from pki.models import CertificateModel


class Command(BaseCommand):
    """Management command to check for expiring or expired certificates.

    Expiring certificates trigger a WARNING notification, while expired certificates trigger a CRITICAL notification.
    """
    help = 'Check for expiring or expired certificates.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None: # noqa: ARG002
        """Entrypoint for the command."""
        self._check_certificate_validity()
        self.stdout.write(self.style.SUCCESS('Certificate validity check completed.'))

    def _check_certificate_validity(self) -> None:
        """Check for certificates that are expiring soon or have already expired.

        Expiring certificates: Within the next 30 days.
        Expired certificates: Already past their `not_valid_after` date.
        """
        expiring_threshold = timezone.now() + timedelta(days=30)
        current_time = timezone.now()

        expiring_certificates = CertificateModel.objects.filter(
            not_valid_after__lte=expiring_threshold,
            not_valid_after__gt=current_time
        )
        expired_certificates = CertificateModel.objects.filter(
            not_valid_after__lte=current_time
        )

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        # Handle expiring certificates
        for cert in expiring_certificates:
            self._create_notification(
                certificate=cert,
                event='CERTIFICATE_EXPIRING',
                notification_type=cast(NotificationModel.NotificationTypes,
                                       NotificationModel.NotificationTypes.WARNING),
                message_type=cast(NotificationModel.NotificationMessageType,
                                  NotificationModel.NotificationMessageType.CERT_EXPIRING),
                new_status=new_status,
            )

        # Handle expired certificates
        for cert in expired_certificates:
            self._create_notification(
                certificate=cert,
                event='CERTIFICATE_EXPIRED',
                notification_type=cast(NotificationModel.NotificationTypes,
                                       NotificationModel.NotificationTypes.CRITICAL),
                message_type=cast(NotificationModel.NotificationMessageType,
                                  NotificationModel.NotificationMessageType.CERT_EXPIRED),
                new_status=new_status,
            )

    def _create_notification(
            self,
            certificate: CertificateModel,
            event: str,
            notification_type: str | NotificationModel.NotificationTypes,
            message_type: str | NotificationModel.NotificationMessageType,
            new_status: NotificationStatus
    ) -> None:
        """Helper function to create a notification for a certificate.

        Skips notification creation if one already exists for the given event and certificate.
        """
        if not NotificationModel.objects.filter(event=event, certificate=certificate).exists():
            message_data = {'common_name': certificate.common_name, 'not_valid_after': certificate.not_valid_after}
            notification = NotificationModel.objects.create(
                certificate=certificate,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=notification_type,
                message_type=message_type,
                event=event,
                message_data=message_data
            )
            notification.statuses.add(new_status)
