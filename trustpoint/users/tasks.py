import datetime
from django.utils import timezone

from devices.models import Device
from pki.models import CertificateModel, BaseCaModel, DomainModel
from home.models import NotificationModel, NotificationMessage, NotificationStatus
import logging
from django.urls import reverse

logger = logging.getLogger('tp.users')
new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


def setup_trustpoint_notifications():
    """
    Task to create initial setup notifications for a new Trustpoint instance.
    This includes a welcome notification and links to the project's GitHub repository and homepage.
    """

    if not NotificationModel.objects.filter(event='EXECUTE_COMMAND_EVENT').exists():
        command_url = '/home/add-domains-and-devices/'

        command_message = NotificationMessage.objects.create(
            short_description='Populate test data',
            long_description=f'Click <a href="{command_url}">here</a> to add test issuing CAs, domains and devices.'
        )

        # Create the notification
        notification = NotificationModel.objects.create(
            event='EXECUTE_COMMAND_EVENT',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=command_message
        )

        notification.statuses.add(new_status)

    if not NotificationModel.objects.filter(event='TRUSTPOINT_DOCUMENTATION').exists():
        documentation_message = NotificationMessage.objects.create(
            short_description='Access the Trustpoint Documentation',
            long_description='You can find the official Trustpoint documentation here: '
                             '<a href="https://industrial-security.io">Trustpoint Documentation</a>'
        )
        notification = NotificationModel.objects.create(
            event='TRUSTPOINT_DOCUMENTATION',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=documentation_message
        )
        notification.statuses.add(new_status)

    # Check if the GitHub and homepage links notification has already been created
    if not NotificationModel.objects.filter(event='TRUSTPOINT_PROJECT_INFO').exists():
        project_info_message = NotificationMessage.objects.create(
            short_description='Explore the Trustpoint project',
            long_description='Visit the Trustpoint GitHub repository for more information: '
                             '<a href="https://github.com/TrustPoint-Project">Trustpoint GitHub</a>\n'
                             'Learn more about industrial security and the Trustpoint project on our '
                             '<a href="https://industrial-security.io">homepage</a>'
        )
        notification = NotificationModel.objects.create(
            event='TRUSTPOINT_PROJECT_INFO',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message=project_info_message
        )
        notification.statuses.add(new_status)

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


def check_certificate_validity():
    """
    Task to check for expiring and expired certificates.
    Expiring certificates trigger a WARNING notification, while expired certificates trigger a CRITICAL notification.
    """
    expiring_threshold = datetime.datetime.now() + datetime.timedelta(days=30)
    expiring_threshold_aware = timezone.make_aware(expiring_threshold)

    current_time = timezone.now()

    expiring_certificates = CertificateModel.objects.filter(not_valid_after__lte=expiring_threshold_aware,
                                                            not_valid_after__gt=current_time)
    expired_certificates = CertificateModel.objects.filter(not_valid_after__lte=current_time)

    logger.info(f"Found {expiring_certificates.count()} expiring certificates.")
    for cert in expiring_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRING', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.common_name} is expiring soon',
                long_description=f'The certificate {cert.common_name} is set to expire on {cert.not_valid_after}.'
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

    logger.info(f"Found {expired_certificates.count()} expired certificates.")
    for cert in expired_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRED', certificate=cert).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Certificate {cert.common_name} has expired',
                long_description=f'The certificate {cert.common_name} expired on {cert.not_valid_after}.'
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


def check_issuing_ca_validity():
    """
    Task to check for both expiring and expired Issuing CAs.
    Expiring CAs trigger a WARNING notification, while expired CAs trigger a CRITICAL notification.
    """
    current_time = timezone.now()
    expiring_threshold = current_time + datetime.timedelta(days=60)

    expiring_issuing_cas = BaseCaModel.objects.filter(
        issuing_ca_certificate__not_valid_after__lte=expiring_threshold,
        issuing_ca_certificate__not_valid_after__gt=current_time  # Still valid, not expired
    )

    expired_issuing_cas = BaseCaModel.objects.filter(
        issuing_ca_certificate__not_valid_after__lte=current_time
    )

    for ca in expiring_issuing_cas:
        if not NotificationModel.objects.filter(event='ISSUING_CA_EXPIRING', issuing_ca=ca).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Issuing CA {ca.unique_name} is expiring soon',
                long_description=f'The issuing CA {ca.unique_name} is set to expire on {ca.issuing_ca_certificate.not_valid_after}.'
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

    for ca in expired_issuing_cas:
        if not NotificationModel.objects.filter(event='ISSUING_CA_EXPIRED', issuing_ca=ca).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Issuing CA {ca.unique_name} has expired',
                long_description=f'The issuing CA {ca.unique_name} expired on {ca.issuing_ca_certificate.not_valid_after}.'
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


def check_domain_issuing_ca():
    """
    Task to create an info notification if a domain has no Issuing CA assigned.
    """
    domains_without_issuing_ca = DomainModel.objects.filter(issuing_ca__isnull=True)

    for domain in domains_without_issuing_ca:
        if not NotificationModel.objects.filter(event='DOMAIN_NO_ISSUING_CA', domain=domain).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Domain {domain.unique_name} has no Issuing CA assigned',
                long_description=f'The domain {domain.unique_name} currently has no Issuing CA assigned.'
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


def check_non_onboarded_devices():
    """
    Task to create an info notification if a device is not onboarded.
    """
    non_onboarded_devices = Device.objects.filter(device_onboarding_status=Device.DeviceOnboardingStatus.NOT_ONBOARDED)

    for device in non_onboarded_devices:
        if not NotificationModel.objects.filter(event='DEVICE_NOT_ONBOARDED', device=device).exists():
            message = NotificationMessage.objects.create(
                short_description=f'Device {device.device_name} is not onboarded in {device.domain}',
                long_description=f'The device {device.device_name} has not completed onboarding.'
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


def check_devices_with_failed_onboarding():
    """
    Task to check if any devices have failed onboarding and create critical notifications.
    """
    failed_onboarding_devices = Device.objects.filter(
        device_onboarding_status=Device.DeviceOnboardingStatus.ONBOARDING_FAILED)

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
