from celery import shared_task
from datetime import datetime, timedelta
from django.utils import timezone

from devices.models import Device
from pki.models import CertificateModel, IssuingCaModel, DomainModel
from home.models import NotificationModel, NotificationMessage, NotificationStatus
import logging

logger = logging.getLogger('tp.users')
new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


@shared_task
def setup_trustpoint_notifications():
    """
    Task to create initial setup notifications for a new Trustpoint instance.
    This includes a welcome notification and links to the project's GitHub repository and homepage.
    """

    # Check if the welcome notification has already been created
    if not NotificationModel.objects.filter(event='WELCOME_TRUSTPOINT').exists():
        welcome_message = NotificationMessage.objects.create(
            short_description='Welcome to Trustpoint!',
            long_description='Thank you for setting up Trustpoint. This system will help you manage your certificates and secure your environment.'
        )
        notification = NotificationModel.objects.create(
            event='WELCOME_TRUSTPOINT',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=welcome_message
        )
        notification.statuses.add(new_status)

    # Check if the GitHub and homepage links notification has already been created
    if not NotificationModel.objects.filter(event='TRUSTPOINT_PROJECT_INFO').exists():
        project_info_message = NotificationMessage.objects.create(
            short_description='Explore the Trustpoint project',
            long_description='Visit the Trustpoint GitHub repository for more information: '
                             '[Trustpoint GitHub](https://github.com/TrustPoint-Project)\n'
                             'Learn more about industrial security and the Trustpoint project on our homepage: '
                             'https://industrial-security.io'
        )
        notification = NotificationModel.objects.create(
            event='TRUSTPOINT_PROJECT_INFO',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=project_info_message
        )
        notification.statuses.add(new_status)

    if not NotificationModel.objects.filter(event='TRUSTPOINT_DOCUMENTATION').exists():
        documentation_message = NotificationMessage.objects.create(
            short_description='Access the Trustpoint Documentation',
            long_description='You can find the official Trustpoint documentation here: '
                             '[Trustpoint Documentation](https://docs.industrial-security.io)'
        )
        NotificationModel.objects.create(
            event='TRUSTPOINT_DOCUMENTATION',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=documentation_message
        )

@shared_task
def check_system_health():
    """
    Task to perform a system health check.
    """
    system_healthy = True
    # TODO (FHKatCSW): Implement logic for system health check

    if not system_healthy:
        message = NotificationMessage.objects.create(
            short_description=f'System health check failed',
            long_description=f'The system health check detected an issue with one or more services. Please investigate immediately.'
        )
        NotificationModel.objects.create(
            event='SYSTEM_NOT_HEALTHY',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.CRITICAL,
            message=message
        )


@shared_task
def check_for_security_vulnerabilities():
    """
    Task to check for known security vulnerabilities in system components.
    """
    vulnerabilities_detected = False
    # TODO (FHKatCSW): Implement logic for vulnerability check

    if vulnerabilities_detected:
        message = NotificationMessage.objects.create(
            short_description=f'Security vulnerability detected',
            long_description=f'A security vulnerability affecting system components has been detected. Immediate attention required.'
        )
        NotificationModel.objects.create(
            event='VULNERABILITY',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.CRITICAL,
            message=message
        )

@shared_task
def check_certificate_validity():
    """
    Task to check if any certificates are expiring soon.
    """
    expiry_threshold = datetime.now() + timedelta(days=30)
    expiring_certificates = CertificateModel.objects.filter(not_valid_after=expiry_threshold)

    logger.info("Task for checking Certificate validity is triggered")

    for cert in expiring_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRING', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.name} is expiring soon',
                long_description=f'The certificate {cert.name} is set to expire on {cert.not_valid_after}.'
            )
            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                event='CERTIFICATE_EXPIRING',
                message=message
            )
            notification.statuses.add(new_status)

@shared_task
def check_issuing_ca_validity():
    """
    Task to check if any issuing CAs are expiring soon.
    """
    expiry_threshold = datetime.now() + timedelta(days=30)
    expiring_issuing_cas = IssuingCaModel.objects.filter(not_valid_after=expiry_threshold)

    for ca in expiring_issuing_cas:
        if not NotificationModel.objects.filter(event='ISSUING_CA_EXPIRING', issuing_ca=ca).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Issuing CA {ca.name} is expiring soon',
                long_description=f'The issuing CA {ca.name} is set to expire on {ca.not_valid_after}.'
            )
            notification = NotificationModel.objects.create(
                issuing_ca=ca,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                event='ISSUING_CA_EXPIRING',
                message=message
            )
            notification.statuses.add(new_status)



@shared_task
def check_expired_certificates():
    """
    Task to create critical notifications if certificates have expired.
    """
    expired_certificates = CertificateModel.objects.filter(not_valid_after=datetime.now())

    for cert in expired_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRED', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.name} has expired',
                long_description=f'The certificate {cert.name} expired on {cert.not_valid_after}.'
            )
            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                event='CERTIFICATE_EXPIRED',
                message=message
            )
            notification.statuses.add(new_status)



@shared_task
def check_expired_issuing_cas():
    """
    Task to create critical notifications if Issuing CAs have expired.
    """
    expired_issuing_cas = IssuingCaModel.objects.filter(not_valid_after=datetime.now())

    for ca in expired_issuing_cas:
        if not NotificationModel.objects.filter(event='ISSUING_CA_EXPIRED', issuing_ca=ca).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Issuing CA {ca.name} has expired',
                long_description=f'The issuing CA {ca.name} expired on {ca.not_valid_after}.'
            )
            notification = NotificationModel.objects.create(
                issuing_ca=ca,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                event='ISSUING_CA_EXPIRED',
                message=message
            )
            notification.statuses.add(new_status)



@shared_task
def check_domain_issuing_ca():
    """
    Task to create an info notification if a domain has no Issuing CA assigned.
    """
    domains_without_issuing_ca = DomainModel.objects.filter(issuing_ca__isnull=True)

    for domain in domains_without_issuing_ca:
        if not NotificationModel.objects.filter(event='DOMAIN_NO_ISSUING_CA', domain=domain).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Domain {domain.name} has no Issuing CA assigned',
                long_description=f'The domain {domain.name} currently has no Issuing CA assigned.'
            )
            notification = NotificationModel.objects.create(
                domain=domain,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DOMAIN,
                notification_type=NotificationModel.NotificationTypes.INFO,
                event='DOMAIN_NO_ISSUING_CA',
                message=message
            )
            notification.statuses.add(new_status)

@shared_task
def check_non_onboarded_devices():
    """
    Task to create an info notification if a device is not onboarded.
    """
    non_onboarded_devices = Device.objects.filter(device_onboarding_status=Device.DeviceOnboardingStatus.NOT_ONBOARDED)

    for device in non_onboarded_devices:
        if not NotificationModel.objects.filter(event='DEVICE_NOT_ONBOARDED', device=device).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Device {device.name} is not onboarded',
                long_description=f'The device {device.name} has not completed onboarding.'
            )
            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.INFO,
                event='DEVICE_NOT_ONBOARDED',
                message=message
            )
            notification.statuses.add(new_status)
@shared_task
def check_devices_with_failed_onboarding():
    """
    Task to check if any devices have failed onboarding and create critical notifications.
    """
    failed_onboarding_devices = Device.objects.filter(device_onboarding_status=Device.DeviceOnboardingStatus.ONBOARDING_FAILED)

    for device in failed_onboarding_devices:
        if not NotificationModel.objects.filter(event='DEVICE_ONBOARDING_FAILED', device=device).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Device {device.device_name} onboarding failed',
                long_description=f'The device {device.device_name} failed onboarding.'
            )
            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                event='DEVICE_ONBOARDING_FAILED',
                message=message
            )
            notification.statuses.add(new_status)

@shared_task
def check_devices_with_revoked_certificates():
    """
    Task to check if any devices have had their certificates revoked and create informational notifications.
    """
    revoked_devices = Device.objects.filter(device_onboarding_status=Device.DeviceOnboardingStatus.REVOKED)

    for device in revoked_devices:
        if not NotificationModel.objects.filter(event='DEVICE_CERTIFICATE_REVOKED', device=device).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Device {device.device_name} certificate revoked',
                long_description=f'The device {device.device_name} has had its certificate revoked. The device may no longer be trusted.'
            )
            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.INFO,
                event='DEVICE_CERTIFICATE_REVOKED',
                message=message
            )
            notification.statuses.add(new_status)


@shared_task
def check_for_weak_signature_algorithms():
    """
    Task to check if any certificates are using weak or deprecated signature algorithms.
    """
    weak_algorithms = ['1.2.840.113549.2.5', '1.3.14.3.2.26']  # OIDs for MD5 and SHA-1

    weak_certificates = CertificateModel.objects.filter(signature_algorithm_oid__in=weak_algorithms)

    for cert in weak_certificates:
        if not NotificationModel.objects.filter(event='WEAK_SIGNATURE_ALGORITHM', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.common_name} uses a weak signature algorithm',
                long_description=f'The certificate {cert.common_name} is signed using {cert.signature_algorithm}, which is considered weak.'
            )
            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='WEAK_SIGNATURE_ALGORITHM',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message=message
            )
            notification.statuses.add(new_status)

@shared_task
def check_for_insufficient_key_length():
    """
    Task to check if any certificates are using insufficient key lengths.
    """
    rsa_minimum_key_size = 2048  # Recommended minimum RSA key size
    insufficient_key_certificates = CertificateModel.objects.filter(
        spki_algorithm_oid='1.2.840.113549.1.1.1',  # OID for RSA
        spki_key_size__lt=rsa_minimum_key_size
    )

    for cert in insufficient_key_certificates:
        if not NotificationModel.objects.filter(event='INSUFFICIENT_KEY_LENGTH', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.common_name} uses insufficient key length',
                long_description=f'The certificate {cert.common_name} uses an RSA key size of {cert.spki_key_size} bits, which is less than the recommended 2048 bits.'
            )
            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='INSUFFICIENT_KEY_LENGTH',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message=message
            )
            notification.statuses.add(new_status)


@shared_task
def check_for_weak_ecc_curves():
    """
    Task to check if any certificates are using deprecated or weak ECC curves.
    """
    weak_ecc_curves = ['1.2.840.10045.3.1.1', '1.3.132.0.33']  # OIDs for weak ECC curves like SECP192R1

    weak_ecc_certificates = CertificateModel.objects.filter(spki_ec_curve_oid__in=weak_ecc_curves)

    for cert in weak_ecc_certificates:
        if not NotificationModel.objects.filter(event='WEAK_ECC_CURVE', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.common_name} uses a weak ECC curve',
                long_description=f'The certificate {cert.common_name} is using the {cert.spki_ec_curve} ECC curve, which is no longer recommended.'
            )
            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='WEAK_ECC_CURVE',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message=message
            )
            notification.statuses.add(new_status)
@shared_task
def test_task():
    """
    Task to test if the celery task is working
    """
    try:
        raise ValueError("TEST")

        message = NotificationMessage.objects.create(
            short_description='Celery test task executed',
            long_description=f'This is a test task to check if Celery is working as expected'
        )
    except Exception as e:
        message = NotificationMessage.objects.create(
            short_description='Exception while Celery test task executed',
            long_description=f'This is a test task to check if Celery is working as expected'
        )
    finally:
        NotificationModel.objects.create(
            notification_type='SETUP',
            notification_source='SYSTEM',
            created_at=timezone.now(),
            message=message
        )

