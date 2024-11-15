import datetime
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from devices import DeviceOnboardingStatus
from devices.models import Device
from pki.models import CertificateModel, BaseCaModel, DomainModel
from home.models import NotificationModel, NotificationMessageModel, NotificationStatus
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

        # Create the notification
        notification = NotificationModel.objects.create(
            event='EXECUTE_COMMAND_EVENT',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message_type=NotificationModel.NotificationMessageType.WELCOME_POPULATE_TEST_DATA,
            message_data={'url':command_url}
        )

        notification.statuses.add(new_status)

    if not NotificationModel.objects.filter(event='TRUSTPOINT_DOCUMENTATION').exists():
        link = '<a href="https://trustpoint.readthedocs.io" target="_blank">Trustpoint Documentation</a>'

        notification = NotificationModel.objects.create(
            event='TRUSTPOINT_DOCUMENTATION',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message_type=NotificationModel.NotificationMessageType.TRUSTPOINT_DOCUMENTATION,
            message_data={'link': link}
        )
        notification.statuses.add(new_status)

    # Check if the GitHub and homepage links notification has already been created
    if not NotificationModel.objects.filter(event='TRUSTPOINT_PROJECT_INFO').exists():
        url_github = 'https://github.com/TrustPoint-Project'
        url_homepage = 'https://industrial-security.io'

        notification = NotificationModel.objects.create(
            event='TRUSTPOINT_PROJECT_INFO',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message_type=NotificationModel.NotificationMessageType.TRUSTPOINT_PROJECT_INFO,
            message_data={'url_github': url_github, 'url_homepage': url_homepage}
        )
        notification.statuses.add(new_status)

    # Check if the welcome notification has already been created
    if not NotificationModel.objects.filter(event='WELCOME_TRUSTPOINT').exists():
        notification = NotificationModel.objects.create(
            event='WELCOME_TRUSTPOINT',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.INFO,
            message_type=NotificationModel.NotificationMessageType.WELCOME_MESSAGE
        )
        notification.statuses.add(new_status)


def check_system_health():
    """
    Task to perform a system health check.
    """
    system_healthy = True
    # TODO (FHKatCSW): Implement logic for system health check

    if not system_healthy:
        NotificationModel.objects.create(
            event='SYSTEM_NOT_HEALTHY',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.CRITICAL,
            message_type=NotificationModel.NotificationMessageType.SYSTEM_NOT_HEALTHY
        )


def check_for_security_vulnerabilities():
    """
    Task to check for known security vulnerabilities in system components.
    """
    vulnerabilities_detected = False
    # TODO (FHKatCSW): Implement logic for vulnerability check

    if vulnerabilities_detected:
        NotificationModel.objects.create(
            event='VULNERABILITY',
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=NotificationModel.NotificationTypes.CRITICAL,
            message_type=NotificationModel.NotificationMessageType.VULNERABILITY
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

    logger.info(f"Found {expiring_certificates.count()} expiring and {expired_certificates.count()} expired certificates.")
    for cert in expiring_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRING', certificate=cert).exists():
            message_data = {'common_name': cert.common_name, 'not_valid_after': cert.not_valid_after}

            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.CERT_EXPIRING,
                event='CERTIFICATE_EXPIRING',
                message_data=message_data
            )
            notification.statuses.add(new_status)

    for cert in expired_certificates:
        if not NotificationModel.objects.filter(event='CERTIFICATE_EXPIRED', certificate=cert).exists():
            message_data = {'common_name': cert.common_name, 'not_valid_after': cert.not_valid_after}

            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                message_type=NotificationModel.NotificationMessageType.CERT_EXPIRED,
                event='CERTIFICATE_EXPIRED',
                message_data=message_data
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
            message_data = {'unique_name': ca.unique_name, 'not_valid_after': ca.issuing_ca_certificate.not_valid_after}

            notification = NotificationModel.objects.create(
                issuing_ca=ca,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.ISSUING_CA_EXPIRING,
                event='ISSUING_CA_EXPIRING',
                message_data=message_data
            )
            notification.statuses.add(new_status)

    for ca in expired_issuing_cas:
        if not NotificationModel.objects.filter(event='ISSUING_CA_EXPIRED', issuing_ca=ca).exists():
            message_data = {'unique_name': ca.unique_name, 'not_valid_after': ca.issuing_ca_certificate.not_valid_after}

            notification = NotificationModel.objects.create(
                issuing_ca=ca,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                message_type=NotificationModel.NotificationMessageType.ISSUING_CA_EXPIRED,
                event='ISSUING_CA_EXPIRED',
                message_data=message_data
            )
            notification.statuses.add(new_status)


def check_domain_issuing_ca():
    """
    Task to create an info notification if a domain has no Issuing CA assigned.
    """
    domains_without_issuing_ca = DomainModel.objects.filter(issuing_ca__isnull=True)

    for domain in domains_without_issuing_ca:
        if not NotificationModel.objects.filter(event='DOMAIN_NO_ISSUING_CA', domain=domain).exists():
            notification = NotificationModel.objects.create(
                domain=domain,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DOMAIN,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.DOMAIN_NO_ISSUING_CA,
                event='DOMAIN_NO_ISSUING_CA',
                message_data={'unique_name': domain.unique_name}
            )
            notification.statuses.add(new_status)


def check_non_onboarded_devices():
    """
    Task to create an info notification if a device is not onboarded.
    """
    non_onboarded_devices = Device.objects.filter(device_onboarding_status=DeviceOnboardingStatus.NOT_ONBOARDED)

    for device in non_onboarded_devices:
        if not NotificationModel.objects.filter(event='DEVICE_NOT_ONBOARDED', device=device).exists():
            message_data = {'device': device.device_name, 'domain': device.domain.unique_name}

            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.DEVICE_NOT_ONBOARDED,
                event='DEVICE_NOT_ONBOARDED',
                message_data=message_data
            )
            notification.statuses.add(new_status)


def check_devices_with_failed_onboarding():
    """
    Task to check if any devices have failed onboarding and create critical notifications.
    """
    failed_onboarding_devices = Device.objects.filter(
        device_onboarding_status=DeviceOnboardingStatus.ONBOARDING_FAILED)

    for device in failed_onboarding_devices:
        if not NotificationModel.objects.filter(event='DEVICE_ONBOARDING_FAILED', device=device).exists():
            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.DEVICE_ONBOARDING_FAILED,
                event='DEVICE_ONBOARDING_FAILED',
                message_data={'device': device.device_name}
            )
            notification.statuses.add(new_status)


def check_devices_with_revoked_certificates():
    """
    Task to check if any devices have had their certificates revoked and create informational notifications.
    """
    revoked_devices = Device.objects.filter(device_onboarding_status=DeviceOnboardingStatus.REVOKED)

    for device in revoked_devices:
        if not NotificationModel.objects.filter(event='DEVICE_CERTIFICATE_REVOKED', device=device).exists():
            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.DEVICE_CERT_REVOKED,
                event='DEVICE_CERTIFICATE_REVOKED',
                message_data={'device': device.device_name}
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
            message_data = {'common_name': cert.common_name, 'signature_algorithm': cert.signature_algorithm}

            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='WEAK_SIGNATURE_ALGORITHM',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.WEAK_SIGNATURE_ALGORITHM,
                message_data=message_data
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
            message_data = {'common_name': cert.common_name, 'spki_key_size': cert.spki_key_size}

            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='INSUFFICIENT_KEY_LENGTH',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.INSUFFICIENT_KEY_LENGTH,
                message_data=message_data
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
            message_data = {'common_name': cert.common_name, 'spki_ec_curve': cert.spki_ec_curve}

            notification = NotificationModel.objects.create(
                certificate=cert,
                created_at=timezone.now(),
                event='WEAK_ECC_CURVE',
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.WEAK_ECC_CURVE,
                message_data=message_data
            )
            notification.statuses.add(new_status)
