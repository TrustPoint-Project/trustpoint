from django.utils import timezone
from django.core.management.base import BaseCommand
from pki.models import DomainModel, CertificateModel, IssuingCaModel
from devices.models import Device
from home.models import NotificationModel, NotificationMessageModel, NotificationStatus


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
            message_data = {'domain': domain.unique_name}

            notification = NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,  # Use TextChoices for notification type
                notification_source=NotificationModel.NotificationSource.DOMAIN,
                message_type = NotificationModel.NotificationMessageType.DOMAIN_TEST,
                message_data=message_data,
                created_at=timezone.now(),
                domain=domain
            )

            notification.statuses.add(new_status)
            self.stdout.write(self.style.SUCCESS(f'Created notification for Domain: {domain.unique_name}'))

        # Create 5 notifications for certificates
        for cert in certificates:
            message_data = {'cn': cert.common_name, 'sn': cert.serial_number}

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                message_type=NotificationModel.NotificationMessageType.CERT_TEST,
                message_data=message_data,
                created_at=timezone.now(),
                certificate=cert
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Certificate: {cert.serial_number}'))

        # Create 5 notifications for issuing CAs
        for ca in issuing_cas:
            message_data = {'ca': ca.unique_name}

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                message_type=NotificationModel.NotificationMessageType.ISSUING_CA_TEST,
                message_data=message_data,
                #message=message,
                created_at=timezone.now(),
                issuing_ca=ca
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Issuing CA: {ca.unique_name}'))

        # Create 5 notifications for devices
        for device in devices:
            message_data = {'device': device.device_serial_number}

            NotificationModel.objects.create(
                notification_type=NotificationModel.NotificationTypes.INFO,
                notification_source=NotificationModel.NotificationSource.DEVICE,
                message_type=NotificationModel.NotificationMessageType.DEVICE_TEST,
                message_data=message_data,
                created_at=timezone.now(),
                device=device
            )
            self.stdout.write(self.style.SUCCESS(f'Created notification for Device: {device.device_serial_number}'))


        # Create a custom notification
        message = NotificationMessageModel.objects.create(
            short_description=f'Custom Notification',
            long_description=f'This notification has no explicit NotificationMessageType set and can contain a custom (non-translatable) message.'
        )

        NotificationModel.objects.create(
            notification_type=NotificationModel.NotificationTypes.INFO,
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            message=message,
            created_at=timezone.now()
        )
