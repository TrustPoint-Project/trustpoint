"""Views for the home application."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.core.management import call_command
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.generic.base import RedirectView, TemplateView
from django_tables2 import RequestConfig

from trustpoint.views.base import TpLoginRequiredMixin

from .filters import NotificationFilter
from .models import NotificationModel, NotificationStatus
from .tables import NotificationTable


class IndexView(TpLoginRequiredMixin, RedirectView):
    """Redirects authenticated users to the index page."""
    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):
    """Renders the dashboard page for authenticated users."""
    template_name = 'home/dashboard.html'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes a DashboardView object with optional and keyword arguments."""
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_notifications(self) -> QuerySet[NotificationModel]:
        """Fetch notification data for the table."""
        return NotificationModel.objects.all()

    def generate_last_week_dates(self) -> list[str]:
        """Generates last week dates as list of string."""
        tz = timezone.get_current_timezone()
        end_date = datetime.now(tz).date()
        start_date = end_date - timedelta(days=6)
        return [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]

    def get_context_data(self, **kwargs: Any) -> HttpResponse:
        """Returns context data."""
        context = super().get_context_data(**kwargs)

        context = self.handle_notifications(context)

        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

    def handle_notifications(self, context: dict[str, Any]) -> HttpResponse:
        """Fetch notification data and filter them."""
        all_notifications = NotificationModel.objects.all()

        notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
        filtered_notifications = notification_filter.qs

        all_notifications_table = NotificationTable(filtered_notifications)
        RequestConfig(self.request, paginate={'per_page': 5}).configure(all_notifications_table)

        context['all_notifications_table'] = all_notifications_table
        context['notification_filter'] = notification_filter

        return context


def notification_details_view(request: HttpRequest, pk: Any) -> HttpResponse:
    """Get notification status and renders notification details"""
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


def mark_as_solved(request: HttpRequest, pk: Any) -> HttpResponse:
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

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Executes the add_domains_and_devices management command and renders view"""
        context = {}

        try:
            # Call the management command
            call_command('add_domains_and_devices')

            # Define success message
            context['status'] = 'success'
            context['message'] = 'The add_domains_and_devices command has been executed successfully.'
        except Exception as e:
            # Define error message
            context['status'] = 'error'
            context['message'] = f'Error executing command: {e}'

        # Render the template with the context
        return render(request, 'home/command_status.html', context)
