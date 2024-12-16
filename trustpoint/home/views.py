import logging
from django.contrib.auth.decorators import login_required
from django.views.generic.base import RedirectView, TemplateView
from django.shortcuts import render, get_object_or_404, redirect
# from django_tables2 import RequestConfig
from datetime import datetime, timedelta

from django.contrib import messages

from trustpoint.views.base import TpLoginRequiredMixin
# from .filters import NotificationFilter
from django.core.management import call_command

from .models import NotificationModel, NotificationStatus
# from .tables import NotificationTable

SUCCESS = 25
ERROR = 40

class IndexView(TpLoginRequiredMixin, RedirectView):
    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):
    template_name = 'home/dashboard.html'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_notifications(self):
        """Fetch notification data for the table."""
        notifications = NotificationModel.objects.all()
        return notifications

    def generate_last_week_dates(self):
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        dates_as_strings = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        return dates_as_strings

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # context = self.handle_notifications(context)

        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

    # def handle_notifications(self, context):
    #     all_notifications = NotificationModel.objects.all()
    #
    #     # notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
    #     # filtered_notifications = notification_filter.qs
    #
    #     all_notifications_table = NotificationTable(filtered_notifications)
    #     RequestConfig(self.request, paginate={"per_page": 5}).configure(all_notifications_table)
    #
    #     context['all_notifications_table'] = all_notifications_table
    #     context['notification_filter'] = notification_filter
    #
    #     return context

@login_required
def notification_details_view(request, pk):
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
        'is_solved': is_solved
    }

    return render(request, 'home/notification_details.html', context)


@login_required
def mark_as_solved(request, pk):
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
        'is_solved': is_solved
    }

    return render(request, 'home/notification_details.html', context)


class AddDomainsAndDevicesView(TpLoginRequiredMixin, TemplateView):
    """View to execute the add_domains_and_devices management command and pass status to the template."""

    _logger = logging.getLogger(__name__)

    def get(self, request, *args, **kwargs):

        try:
            call_command('add_domains_and_devices')

            messages.add_message(
                request,
                SUCCESS,
                'Successfully added test data.'
            )
        except Exception as e:
            # TODO(AlexHx8472): Catch the correct and proper error messages.
            messages.add_message(
                request,
                ERROR,
                f'Test data already available in the Database.'
            )

        return redirect('home:dashboard')
