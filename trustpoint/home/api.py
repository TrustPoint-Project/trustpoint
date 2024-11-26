"""API endpoints for the home app."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any

from devices import DeviceOnboardingStatus
from devices.models import Device
from django.db.models import Case, Count, F, IntegerField, Q, Value, When
from django.db.models.functions import TruncDate
from django.utils import dateparse, timezone
from ninja import Router
from ninja.responses import Response
from pki import CaLocalization, CertificateStatus, TemplateName
from pki.models import BaseCaModel, CertificateModel, DomainModel, IssuedDeviceCertificateModel, IssuingCaModel

if TYPE_CHECKING:
    from django.http import HttpRequest

logger = logging.getLogger('tp.home')
router = Router()

def get_device_count_by_onboarding_status(start_date: date) -> dict[str, Any]:
    """Get device count by onboarding status from database"""
    device_os_counts = {str(status): 0 for _, status in DeviceOnboardingStatus.choices}
    try:
        device_os_qr = (
            Device.objects.filter(created_at__gt=start_date)
            .values('device_onboarding_status')
            .annotate(count=Count('device_onboarding_status'))
        )
    except Exception:
        logger.exception('Error occurred in device count by onboarding protocol query')
    # Mapping from short code to human-readable name
    protocol_mapping = {key: str(value) for key, value in DeviceOnboardingStatus.choices}
    device_os_counts = {protocol_mapping[item['device_onboarding_status']]: item['count'] for item in device_os_qr}

    for protocol in protocol_mapping.values():
        device_os_counts.setdefault(protocol, 0)
    device_os_counts['total'] = sum(device_os_counts.values())
    return device_os_counts


def get_cert_counts() -> dict[str, Any]:
    """Get certificate counts from database"""
    cert_counts = {}
    # Get the current date and the dates for 7 days and 1 day ahead
    now = timezone.now()
    next_7_days = now + timedelta(days=7)
    next_1_day = now + timedelta(days=1)
    try:
        cert_counts = CertificateModel.objects.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(not_valid_after__gt=now)),
            expired=Count('id', filter=Q(not_valid_after__lt=now)),
            expiring_in_7_days=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_7_days)),
            expiring_in_1_day=Count('id', filter=Q(not_valid_after__gt=now, not_valid_after__lte=next_1_day)),
        )
    except Exception:
        logger.exception('Error occurred in certificate count query')
    return cert_counts


def get_cert_counts_by_status_and_date() -> dict[str, Any]:
    """Get certificate counts grouped by issue date and certificate status."""
    cert_counts_by_status = []
    try:
        cert_status_qr = (
            CertificateModel.objects.filter(
                certificate_status__in=['O', 'R']
            )  # Optional: Filter nach mehreren Statuswerten
            .annotate(issue_date=TruncDate('not_valid_before'))
            .values('issue_date', 'certificate_status')
            .annotate(cert_count=Count('id'))
            .order_by('issue_date', 'certificate_status')
        )
        # Mapping von Status-Code zu lesbarem Namen
        status_mapping = dict(CertificateStatus.choices)
        # Konvertiere das QuerySet in eine Liste und formatiere die Werte
        cert_counts_by_status = [
            {
                'issue_date': item['issue_date'].strftime('%Y-%m-%d'),
                'certificate_status': status_mapping.get(item['certificate_status'], item['certificate_status']),
                'cert_count': item['cert_count'],
            }
            for item in cert_status_qr
        ]
    except Exception:
        logger.exception('Error occurred in certificate count by status query')
    return cert_counts_by_status


def get_cert_counts_by_status(start_date: date) -> dict[str, Any]:
    """Get certs count by onboarding status from database"""
    cert_status_counts = {str(status): 0 for _, status in CertificateStatus.choices}
    try:
        cert_status_qr = (
            CertificateModel.objects.filter(added_at__gt=start_date)
            .values('certificate_status')
            .annotate(count=Count('certificate_status'))
        )
        # Mapping from short code to human-readable name
        status_mapping = {key: str(value) for key, value in CertificateStatus.choices}
        cert_status_counts = {status_mapping[item['certificate_status']]: item['count'] for item in cert_status_qr}
        cert_status_counts['total'] = sum(cert_status_counts.values())
    except Exception:
        logger.exception('Error occurred in cert counts by status query')
    return cert_status_counts


def get_issuing_ca_counts() -> dict[str, Any]:
    """Get issuing CA counts from database"""
    # Current date
    today = timezone.now().date()
    issuing_ca_counts = {}
    try:
        # Query to get total, active, and expired Issuing CAs
        issuing_ca_counts = IssuingCaModel.objects.aggregate(
            total=Count('id'),
            active=Count(
                Case(
                    When(issuing_ca_certificate__not_valid_after__gt=today, then=Value(1)), output_field=IntegerField()
                )
            ),
            expired=Count(
                Case(
                    When(issuing_ca_certificate__not_valid_after__lte=today, then=Value(1)), output_field=IntegerField()
                )
            ),
        )
    except Exception:
        logger.exception('Error occurred in issuing ca count query')

    return issuing_ca_counts


def get_device_counts_by_date_and_status() -> dict[str, Any]:
    """Get device count by date and onboarding status from database"""
    device_counts_by_date_and_os = {}
    try:
        device_date_os_qr = (
            Device.objects.annotate(issue_date=TruncDate('created_at'))
            .values('issue_date', onboarding_status=F('device_onboarding_status'))
            .annotate(device_count=Count('id'))
            .order_by('issue_date', 'device_onboarding_status')
        )
        # Convert the queryset to a list
        device_counts_by_date_and_os = list(device_date_os_qr)
    except Exception:
        logger.exception('Error occurred in device count by domain query')
    return device_counts_by_date_and_os

def get_device_count_by_onboarding_protocol(start_date: date) -> dict[str, Any]:
    """Get device count by onboarding protocol from database"""
    device_op_counts = {str(status): 0 for _, status in Device.OnboardingProtocol.choices}
    try:
        device_op_qr = (
            Device.objects.filter(created_at__gt=start_date)
            .values('onboarding_protocol')
            .annotate(count=Count('onboarding_protocol'))
        )
        # Mapping from short code to human-readable name
        protocol_mapping = {key: str(value) for key, value in Device.OnboardingProtocol.choices}
        device_op_counts = {protocol_mapping[item['onboarding_protocol']]: item['count'] for item in device_op_qr}

    except Exception:
        logger.exception('Error occurred in device count by onboarding protocol query')
    return device_op_counts


def get_device_count_by_domain(start_date: date) -> dict[str, Any]:
    """Get count of onboarded devices by domain from the database."""
    try:
        device_domain_qr = DomainModel.objects.annotate(
            onboarded_device_count=Count(
                'device', filter=Q(device__device_onboarding_status='O') & Q(device__created_at__gt=start_date)
            )
        ).values('unique_name', 'onboarded_device_count')
        # Convert the queryset to a list
        return list(device_domain_qr)
    except Exception:
        logger.exception('Error occurred in device count by domain query')
        return []

def get_cert_counts_by_issuing_ca(start_date: date) -> dict[str, Any]:
    """Get certificate count by issuing ca from database"""
    cert_counts_by_issuing_ca = {}
    try:
        cert_issuing_ca_qr = (
            CertificateModel.objects.filter(issuing_ca_model__isnull=False)
            .filter(added_at__gt=start_date)
            .annotate(cert_count=Count('issued_certificate_references'))
            .values('cert_count', ca_name=F('issuing_ca_model__unique_name'))
        )
        # Convert the queryset to a list
        cert_counts_by_issuing_ca = list(cert_issuing_ca_qr)
    except Exception:
        logger.exception('Error occurred in certificate count by issuing ca query')

    return cert_counts_by_issuing_ca


def get_cert_counts_by_issuing_ca_and_date() -> dict[str, Any]:
    """Get certificate count by issuing ca from database"""
    cert_counts_by_issuing_ca_and_date = {}
    try:
        cert_issuing_ca_and_date_qr = (
            CertificateModel.objects.filter(issuer_references__issuing_ca_model__isnull=True)
            .annotate(issue_date=TruncDate('added_at'))
            .values('issue_date', name=F('issuing_ca_model__unique_name'))
            .annotate(cert_count=Count('issued_certificate_references'))
            .filter(name__isnull=False)
            .order_by('added_at', 'name')
        )
        # Convert the queryset to a list
        cert_counts_by_issuing_ca_and_date = list(cert_issuing_ca_and_date_qr)
    except Exception:
        logger.exception('Error occurred in certificate count by issuing ca query')
    return cert_counts_by_issuing_ca_and_date


def get_cert_counts_by_domain(start_date: date) -> dict[str, Any]:
    """Get certificate count by domain from database"""
    cert_counts_by_domain = {}
    try:
        cert_domain_qr = (
            IssuedDeviceCertificateModel.objects.filter(certificate__added_at__gt=start_date)
            .values(unique_name=F('domain__unique_name'))
            .annotate(cert_count=Count('domain'))
        )

        # Convert the queryset to a list
        cert_counts_by_domain = list(cert_domain_qr)
    except Exception:
        logger.exception('Error occurred in certificate count by issuing ca query')
    return cert_counts_by_domain


def get_cert_counts_by_template(start_date: date) -> dict[str, Any]:
    """Get certificate count by template from database"""
    cert_counts_by_template = {str(status): 0 for _, status in TemplateName.choices}
    try:
        cert_template_qr = (
            IssuedDeviceCertificateModel.objects.filter(certificate__added_at__gt=start_date)
            .values('template_name')
            .annotate(count=Count('template_name'))
        )
        # Mapping from short code to human-readable name
        template_mapping = {key: str(value) for key, value in TemplateName.choices}
        cert_counts_by_template = {template_mapping[item['template_name']]: item['count'] for item in cert_template_qr}
    except Exception:
        logger.exception('Error occurred in certificate count by template query')
    return cert_counts_by_template


def get_issuing_ca_counts_by_type(start_date: date) -> dict[str, Any]:
    """Get issuing ca counts by type from database"""
    issuing_ca_type_counts = {str(cert_type): 0 for _, cert_type in CaLocalization.choices}
    try:
        ca_type_qr = (
            BaseCaModel.objects.filter(added_at__gt=start_date)
            .values('ca_localization')
            .annotate(count=Count('ca_localization'))
        )
        # Mapping from short code to human-readable name
        protocol_mapping = {key: str(value) for key, value in CaLocalization.choices}
        issuing_ca_type_counts = {protocol_mapping[item['ca_localization']]: item['count'] for item in ca_type_qr}

    except Exception:
        logger.exception('Error occurred in ca counts by type query')
    return issuing_ca_type_counts

# --- PUBLIC HOME API ENDPOINTS ---
@router.get('/dashboard_data', exclude_none=True)
def dashboard_data(request: HttpRequest, start_date: str | None) -> dict[str, Any]:
    """Get dashboard data for panels, tables and charts"""
    start_date_object = None
    # Parse the date string into a datetime.date object
    if start_date:
        start_date_object = dateparse.parse_date(start_date)  # Returns a date object (not datetime)
        if not start_date_object:
            return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)
    else:
        tz = timezone.get_current_timezone()
        start_date_object = datetime.now(tz).date()

    dashboard_data = {}

    device_counts = get_device_count_by_onboarding_status(dateparse.parse_date('2023-01-01'))
    dashboard_data['device_counts'] = device_counts

    cert_counts = get_cert_counts()
    if cert_counts:
        dashboard_data['cert_counts'] = cert_counts

    issuing_ca_counts = get_issuing_ca_counts()
    if issuing_ca_counts:
        dashboard_data['issuing_ca_counts'] = issuing_ca_counts

    device_counts_by_os = get_device_count_by_onboarding_status(start_date_object)
    if device_counts_by_os:
        dashboard_data['device_counts_by_os'] = device_counts_by_os

    device_counts_by_date_and_os = get_device_counts_by_date_and_status()
    if device_counts_by_date_and_os:
        dashboard_data['device_counts_by_date_and_os'] = device_counts_by_date_and_os

    device_counts_by_op = get_device_count_by_onboarding_protocol(start_date_object)
    if device_counts_by_op:
        dashboard_data['device_counts_by_op'] = device_counts_by_op

    device_counts_by_domain = get_device_count_by_domain(start_date_object)
    if device_counts_by_domain:
        dashboard_data['device_counts_by_domain'] = device_counts_by_domain

    cert_counts_by_domain = get_cert_counts_by_domain(start_date_object)
    if cert_counts_by_domain:
        dashboard_data['cert_counts_by_domain'] = cert_counts_by_domain

    cert_counts_by_template = get_cert_counts_by_template(start_date_object)
    if cert_counts_by_template:
        dashboard_data['cert_counts_by_template'] = cert_counts_by_template

    cert_counts_by_issuing_ca = get_cert_counts_by_issuing_ca(start_date_object)
    if cert_counts_by_issuing_ca:
        dashboard_data['cert_counts_by_issuing_ca'] = cert_counts_by_issuing_ca

    cert_counts_by_issuing_ca_and_date = get_cert_counts_by_issuing_ca_and_date()
    if cert_counts_by_issuing_ca_and_date:
        dashboard_data['cert_counts_by_issuing_ca_and_date'] = cert_counts_by_issuing_ca_and_date

    issuing_ca_counts_by_type = get_issuing_ca_counts_by_type(start_date_object)
    if issuing_ca_counts_by_type:
        dashboard_data['ca_counts_by_type'] = issuing_ca_counts_by_type

    cert_counts_by_status = get_cert_counts_by_status(start_date_object)
    if cert_counts_by_status:
        dashboard_data['cert_counts_by_status'] = cert_counts_by_status
    logger.info('dashboard data %s', dashboard_data)
    return Response(dashboard_data)
