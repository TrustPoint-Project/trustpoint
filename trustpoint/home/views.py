"""Contains views that handle HTTP requests and return appropriate responses for the application."""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import Any

from devices.models import DeviceModel, IssuedCredentialModel
from django.contrib import messages  # type: ignore[import-untyped]
from django.contrib.auth.decorators import login_required  # type: ignore[import-untyped]
from django.core.management import call_command  # type: ignore[import-untyped]
from django.db.models import Case, Count, F, IntegerField, Q, QuerySet, Value, When  # type: ignore[import-untyped]
from django.db.models.functions import TruncDate  # type: ignore[import-untyped]
from django.http import HttpRequest, HttpResponse, JsonResponse  # type: ignore[import-untyped]
from django.shortcuts import get_object_or_404, redirect, render  # type: ignore[import-untyped]
from django.utils import dateparse, timezone  # type: ignore[import-untyped]
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import RedirectView, TemplateView  # type: ignore[import-untyped]
from django.views.generic.list import ListView
from ninja.responses import Response
from pki.models import CertificateModel, IssuingCaModel

from trustpoint.views.base import TpLoginRequiredMixin, SortableTableMixin

from .filters import NotificationFilter
from .models import NotificationModel, NotificationStatus

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.utils.safestring import SafeString  # type: ignore[import-untyped]

SUCCESS = 25
ERROR = 40


class IndexView(TpLoginRequiredMixin, RedirectView):
    """Redirects authenticated users to the dashboard page."""

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, SortableTableMixin, ListView):
    """Renders the dashboard page for authenticated users. Uses the 'home/dashboard.html' template."""

    template_name = 'home/dashboard.html'
    model = NotificationModel
    context_object_name = 'notifications'
    default_sort_param = '-created_at'
    paginate_by = 30

    def __init__(self, *args: tuple, **kwargs: dict) -> None:
        """Initializes the parent class with the given arguments and keyword arguments."""
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_notifications(self) -> QuerySet[NotificationModel]:
        """Fetch notification data for the table."""
        return NotificationModel.objects.all()

    def generate_last_week_dates(self) -> list[str]:
        """Generates date strings for last one week"""
        end_date = timezone.now()
        start_date = end_date - timedelta(days=6)
        return [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]

    def get_queryset(self) -> QuerySet[NotificationModel]:
        all_notifications = NotificationModel.objects.all()

        notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
        self.queryset = notification_filter.qs
        return super().get_queryset()

    def get_context_data(self, **kwargs: dict) -> dict[str, Any]:
        """Fetch context data"""
        context = super().get_context_data(**kwargs)

        for notification in context['notifications']:
            notification.type_badge = self._render_notification_type(notification)
            notification.created = self._render_created_at(notification)

        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

    @staticmethod
    def _render_created_at(record: NotificationModel) -> SafeString:
        """Render the created_at field with a badge if the status is 'New'."""
        created_at_display = record.created_at.strftime('%Y-%m-%d %H:%M:%S')

        if record.statuses.filter(status=NotificationStatus.StatusChoices.NEW).exists():
            return format_html('{} <span class="badge bg-secondary">{}</span>', created_at_display, _('New'))

        return format_html('{}', created_at_display)

    @staticmethod
    def _render_notification_type(record: NotificationModel) -> SafeString:
        """Render the notification type with a badge according to the type."""
        type_display = record.get_notification_type_display()

        if record.notification_type == NotificationModel.NotificationTypes.CRITICAL:
            badge_class = 'bg-danger'
        elif record.notification_type == NotificationModel.NotificationTypes.WARNING:
            badge_class = 'bg-warning'
        elif record.notification_type == NotificationModel.NotificationTypes.INFO:
            badge_class = 'bg-info'
        else:  # Setup or other types default to secondary
            badge_class = 'bg-secondary'

        return format_html('<span class="badge {}">{}</span>', badge_class, type_display)


@login_required
def notification_details_view(request: HttpRequest, pk: int | str) -> HttpResponse:
    """Rends notification details view"""
    notification = get_object_or_404(NotificationModel, pk=pk)

    notification_statuses = notification.statuses.values_list('status', flat=True)

    new_status, created = NotificationStatus.objects.get_or_create(status='NEW')
    solved_status, created = NotificationStatus.objects.get_or_create(status='SOLVED')
    is_solved = solved_status in notification.statuses.all()

    if new_status and new_status in notification.statuses.all():
        notification.statuses.remove(new_status)

    context = {
        'notification': notification,
        'NotificationStatus': NotificationStatus,
        'notification_statuses': notification_statuses,
        'is_solved': is_solved,
    }

    return render(request, 'home/notification_details.html', context)


@login_required
def mark_as_solved(request: HttpRequest, pk: int | str) -> HttpResponse:
    """View to mark the notification as Solved."""
    notification = get_object_or_404(NotificationModel, pk=pk)

    solved_status, created = NotificationStatus.objects.get_or_create(status='SOLVED')
    is_solved = solved_status in notification.statuses.all()

    if solved_status:
        notification.statuses.add(solved_status)

    notification_statuses = notification.statuses.values_list('status', flat=True)

    context = {
        'notification': notification,
        'NotificationStatus': NotificationStatus,
        'notification_statuses': notification_statuses,
        'is_solved': is_solved,
    }

    return render(request, 'home/notification_details.html', context)


class AddDomainsAndDevicesView(TpLoginRequiredMixin, TemplateView):
    """View to execute the add_domains_and_devices management command and pass status to the template."""

    _logger = logging.getLogger(__name__)

    def get(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Handles GET requests and redirects to the dashboard."""
        try:
            call_command('add_domains_and_devices')

            messages.add_message(request, SUCCESS, 'Successfully added test data.')
        except Exception:
            # TODO(AlexHx8472): Catch the correct and proper error messages.
            messages.add_message(request, ERROR, 'Test data already available in the Database.')

        return redirect('home:dashboard')


class DashboardChartsAndCountsView(TpLoginRequiredMixin, TemplateView):
    """View to mark the notification as Solved."""

    _logger = logging.getLogger(__name__)

    def get(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Get dashboard data for panels, tables and charts"""
        start_date: str = request.GET.get('start_date', None)
        start_date_object = None
        # Parse the date string into a datetime.date object
        if start_date:
            start_date_object = dateparse.parse_datetime(start_date)  # Returns a datetime object
            if not start_date_object:
                return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=400)
        else:
            tz = timezone.get_current_timezone()
            start_date_object = datetime.now(tz).date()

        dashboard_data: dict[str, Any] = {}

        start_date_object = timezone.make_aware(start_date_object)

        device_counts = self.get_device_count_by_onboarding_status(dateparse.parse_date('2023-01-01'))
        dashboard_data['device_counts'] = device_counts
        self._logger.debug('device counts %s', device_counts)

        cert_counts = self.get_cert_counts()
        if cert_counts:
            dashboard_data['cert_counts'] = cert_counts

        issuing_ca_counts = self.get_issuing_ca_counts()
        if issuing_ca_counts:
            dashboard_data['issuing_ca_counts'] = issuing_ca_counts

        self.get_device_charts_data(dashboard_data, start_date_object)
        self.get_cert_charts_data(dashboard_data, start_date_object)
        self.get_ca_charts_data(dashboard_data, start_date_object)

        return JsonResponse(dashboard_data)

    def get_device_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for device charts"""
        device_counts_by_os = self.get_device_count_by_onboarding_status(start_date_object)
        if device_counts_by_os:
            dashboard_data['device_counts_by_os'] = device_counts_by_os

        device_counts_by_op = self.get_device_count_by_onboarding_protocol(start_date_object)
        if device_counts_by_op:
            dashboard_data['device_counts_by_op'] = device_counts_by_op

        device_counts_by_domain = self.get_device_count_by_domain(start_date_object)
        if device_counts_by_domain:
            dashboard_data['device_counts_by_domain'] = device_counts_by_domain

    def get_cert_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for certificate charts"""
        cert_counts_by_status = self.get_cert_counts_by_status(start_date_object)
        if cert_counts_by_status:
            dashboard_data['cert_counts_by_status'] = cert_counts_by_status

        cert_counts_by_domain = self.get_cert_counts_by_domain(start_date_object)
        if cert_counts_by_domain:
            dashboard_data['cert_counts_by_domain'] = cert_counts_by_domain

        cert_counts_by_template = self.get_cert_counts_by_template(start_date_object)
        if cert_counts_by_template:
            dashboard_data['cert_counts_by_template'] = cert_counts_by_template

    def get_ca_charts_data(self, dashboard_data: dict[str, Any], start_date_object: datetime) -> None:
        """Fetch data from database for issuing ca charts"""
        cert_counts_by_issuing_ca = self.get_cert_counts_by_issuing_ca(start_date_object)
        if cert_counts_by_issuing_ca:
            dashboard_data['cert_counts_by_issuing_ca'] = cert_counts_by_issuing_ca

        cert_counts_by_issuing_ca_and_date = self.get_cert_counts_by_issuing_ca_and_date(start_date_object)
        if cert_counts_by_issuing_ca_and_date:
            dashboard_data['cert_counts_by_issuing_ca_and_date'] = cert_counts_by_issuing_ca_and_date

        issuing_ca_counts_by_type = self.get_issuing_ca_counts_by_type(start_date_object)
        if issuing_ca_counts_by_type:
            dashboard_data['ca_counts_by_type'] = issuing_ca_counts_by_type

    def get_device_count_by_onboarding_status(self, start_date: datetime) -> dict[str, Any]:
        """Get device count by onboarding status from database"""
        device_os_counts = {str(status): 0 for _, status in DeviceModel.OnboardingStatus.choices}
        try:
            device_os_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date)
                .values('onboarding_status')
                .annotate(count=Count('onboarding_status'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in DeviceModel.OnboardingStatus.choices}
            device_os_counts = {protocol_mapping[item['onboarding_status']]: item['count'] for item in device_os_qr}

            for protocol in protocol_mapping.values():
                device_os_counts.setdefault(protocol, 0)
            device_os_counts['total'] = sum(device_os_counts.values())
        except Exception:
            self._logger.exception('Error occurred in device count by onboarding protocol query')

        return device_os_counts

    def get_cert_counts(self) -> dict[str, Any]:
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
            self._logger.exception('Error occurred in certificate count query')
        return cert_counts

    def get_cert_counts_by_status_and_date(self) -> list[dict[str, Any]]:
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
            status_mapping = dict(CertificateModel.CertificateStatus.choices)
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
            self._logger.exception('Error occurred in certificate count by status query')
        return cert_counts_by_status

    def get_cert_counts_by_status(self, start_date: datetime) -> dict[str, Any]:
        """Get certs count by onboarding status from database"""
        cert_status_counts = {str(status): 0 for _, status in CertificateModel.CertificateStatus.choices}
        try:
            cert_status_qr = (
                CertificateModel.objects.filter(created_at__gt=start_date)
                .values('certificate_status')
                .annotate(count=Count('certificate_status'))
            )
            # Mapping from short code to human-readable name
            status_mapping = {key: str(value) for key, value in CertificateModel.CertificateStatus.choices}
            cert_status_counts = {status_mapping[item['certificate_status']]: item['count'] for item in cert_status_qr}
            cert_status_counts['total'] = sum(cert_status_counts.values())
        except Exception:
            self._logger.exception('Error occurred in cert counts by status query')
        return cert_status_counts

    def get_issuing_ca_counts(self) -> dict[str, Any]:
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
                        When(credential__certificates__not_valid_after__gt=today, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
                expired=Count(
                    Case(
                        When(credential__certificates__not_valid_after__lte=today, then=Value(1)),
                        output_field=IntegerField(),
                    )
                ),
            )
        except Exception:
            self._logger.exception('Error occurred in issuing ca count query')

        return issuing_ca_counts

    def get_device_counts_by_date_and_status(self) -> list[dict[str, Any]]:
        """Get device count by date and onboarding status from database"""
        device_counts_by_date_and_os = []
        try:
            device_date_os_qr = (
                DeviceModel.objects.annotate(issue_date=TruncDate('created_at'))
                .values('issue_date', onboarding_status=F('onboarding_status'))
                .annotate(device_count=Count('id'))
                .order_by('issue_date', 'onboarding_status')
            )
            # Convert the queryset to a list
            device_counts_by_date_and_os = list(device_date_os_qr)
        except Exception:
            self._logger.exception('Error occurred in device count by date and onboarding status')
        return device_counts_by_date_and_os

    def get_device_count_by_onboarding_protocol(self, start_date: datetime) -> dict[str, Any]:
        """Get device count by onboarding protocol from database"""
        device_op_counts = {str(status): 0 for _, status in DeviceModel.OnboardingProtocol.choices}
        try:
            device_op_qr = (
                DeviceModel.objects.filter(created_at__gt=start_date)
                .values('onboarding_protocol')
                .annotate(count=Count('onboarding_protocol'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in DeviceModel.OnboardingProtocol.choices}
            device_op_counts = {protocol_mapping[item['onboarding_protocol']]: item['count'] for item in device_op_qr}

        except Exception:
            self._logger.exception('Error occurred in device count by onboarding protocol query')
        return device_op_counts

    def get_device_count_by_domain(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get count of onboarded devices by domain from the database."""
        try:
            device_domain_qr = (
                DeviceModel.objects.filter(
                    Q(onboarding_status=DeviceModel.OnboardingStatus.ONBOARDED) & Q(created_at__gte=start_date)
                )
                .values(domain_name=F('domain__unique_name'))
                .annotate(onboarded_device_count=Count('id'))
            )

            # Convert the queryset to a list
            return list(device_domain_qr)
        except Exception:
            self._logger.exception('Error occurred in device count by domain query')
            return []

    def get_cert_counts_by_issuing_ca(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get certificate count by issuing ca from database"""
        cert_counts_by_issuing_ca = []
        try:
            cert_issuing_ca_qr = (
                CertificateModel.objects.filter(issuer__isnull=False)
                .filter(created_at__gt=start_date)
                .values(ca_name=F('issuer__value'))
                .annotate(cert_count=Count('id'))
            )
            # Convert the queryset to a list
            cert_counts_by_issuing_ca = list(cert_issuing_ca_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')

        return cert_counts_by_issuing_ca

    def get_cert_counts_by_issuing_ca_and_date(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get certificate count by issuing ca from database"""
        cert_counts_by_issuing_ca_and_date = []
        try:
            cert_issuing_ca_and_date_qr = (
                CertificateModel.objects.filter(issuer__isnull=False)
                .filter(created_at__gt=start_date)
                .annotate(issue_date=TruncDate('created_at'))
                .values('issue_date', name=F('issuer__value'))
                .annotate(cert_count=Count('id'))
                .order_by('issue_date', 'name')
            )
            # Convert the queryset to a list
            cert_counts_by_issuing_ca_and_date = list(cert_issuing_ca_and_date_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')
        return cert_counts_by_issuing_ca_and_date

    def get_cert_counts_by_domain(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get certificate count by domain from database"""
        cert_counts_by_domain = []
        try:
            cert_counts_domain_qr = (
                IssuedCredentialModel.objects.filter(created_at__gt=start_date)
                .values(domain_name=F('domain__unique_name'))
                .annotate(cert_count=Count('id'))
            )

            # cert_domain_counts = (
            #     IssuedDomainCredentialModel.objects.filter(created_at__gt=start_date)
            #     .values(domain_name=F('domain__unique_name'))
            #     .annotate(cert_count=Count('id'))
            # )

            # Use a union query to combine results
            #cert_domain_qr = cert_app_counts.union(cert_domain_counts)

            #   # Convert the queryset to a list
            cert_counts_by_domain = list(cert_counts_domain_qr)
        except Exception:
            self._logger.exception('Error occurred in certificate count by issuing ca query')
        return cert_counts_by_domain

    def get_cert_counts_by_template(self, start_date: datetime) -> dict[str, Any]:
        """Get certificate count by template from database"""
        cert_counts_by_template = {
            str(status): 0 for _, status in IssuedCredentialModel.IssuedCredentialPurpose.choices
        }
        try:
            cert_template_qr = (
                IssuedCredentialModel.objects.filter(
                    credential__certificates__created_at__gt=start_date
                )
                .values(cert_type=F('issued_credential_purpose'))
                .annotate(count=Count('credential__certificates'))
            )
            # Mapping from short code to human-readable name
            template_mapping = {
                key: str(value) for key, value in IssuedCredentialModel.IssuedCredentialPurpose.choices
            }
            cert_counts_by_template = {template_mapping[item['cert_type']]: item['count'] for item in cert_template_qr}
        except Exception:
            self._logger.exception('Error occurred in certificate count by template query')
        return cert_counts_by_template

    def get_issuing_ca_counts_by_type(self, start_date: datetime) -> dict[str, Any]:
        """Get issuing ca counts by type from database"""
        issuing_ca_type_counts = {str(cert_type): 0 for _, cert_type in IssuingCaModel.IssuingCaTypeChoice.choices}
        try:
            ca_type_qr = (
                IssuingCaModel.objects.filter(created_at__gt=start_date)
                .values('issuing_ca_type')
                .annotate(count=Count('issuing_ca_type'))
            )
            # Mapping from short code to human-readable name
            protocol_mapping = {key: str(value) for key, value in IssuingCaModel.IssuingCaTypeChoice.choices}
            issuing_ca_type_counts = {protocol_mapping[item['issuing_ca_type']]: item['count'] for item in ca_type_qr}

        except Exception:
            self._logger.exception('Error occurred in ca counts by type query')
        return issuing_ca_type_counts
