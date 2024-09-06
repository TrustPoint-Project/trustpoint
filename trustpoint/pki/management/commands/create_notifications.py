from django.utils import timezone
from django.core.management.base import BaseCommand
from pki.models import DomainModel, CertificateModel, IssuingCaModel
from devices.models import Device
from home.models import NotificationModel, NotificationMessage, NotificationStatus


class Command(BaseCommand):
    """Django management command for adding 5 notifications for each system, domain, device, issuing CA, and certificate."""

    help = 'Creates 5 notifications for Systems, Domains, Devices, Issuing CAs, and Certificates.'

    def handle(self, *args, **kwargs) -> None:
        """The logic to query models and create 5 notifications for each type."""

        domains = DomainModel.objects.all()[:5]
        certificates = CertificateModel.objects.all()[:5]
        issuing_cas = IssuingCaModel.objects.all()[:5]
        devices = Device.objects.all()[:5]

        new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


        # Create 5 notifications for domains
        for domain in domains:
            message = NotificationMessage.objects.create(
                short_description=f'Domain: {domain.unique_name}',
                long_description=f'Notification for Domain: {domain.unique_name}'
            )

            notification = NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,  # Use TextChoices for notification type
                notification_source=NotificationModel.NotificationSource.DOMAIN,
                message=message,
                created_at=timezone.now(),
            )

            notification.statuses.add(new_status)
            self.stdout.write(self.style.SUCCESS(f'Created notification for Domain: {domain.unique_name}'))

        # Create 5 notifications for certificates
        for cert in certificates:
            message = NotificationMessage.objects.create(
                short_description=f'Certificate: {cert.serial_number}',
                long_description=f'Notification for Certificate: {cert.serial_number}'
            )

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                message=message,
                created_at=timezone.now()
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Certificate: {cert.serial_number}'))

        # Create 5 notifications for issuing CAs
        for ca in issuing_cas:
            message = NotificationMessage.objects.create(
                short_description=f'Issuing CA: {ca.unique_name}',
                long_description=f'Notification for Issuing CA: {ca.unique_name}'
            )

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,  # Use TextChoices for notification type
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                message=message,
                created_at=timezone.now()
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Issuing CA: {ca.unique_name}'))

        # Create 5 notifications for devices
        for device in devices:
            message = NotificationMessage.objects.create(
                short_description=f'Device: {device.device_serial_number}',
                long_description=f'Notification for Device: {device.device_serial_number}'
            )

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,
                notification_source=NotificationModel.NotificationSource.DEVICE,
                message=message,
                created_at=timezone.now()
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Device: {device.device_serial_number}'))
