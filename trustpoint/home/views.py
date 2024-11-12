import json
from django.views.generic.base import RedirectView, TemplateView
from django.shortcuts import render, get_object_or_404, redirect
from django_tables2 import RequestConfig
from datetime import datetime, timedelta
from trustpoint.views.base import TpLoginRequiredMixin, ContextDataMixin
from .filters import NotificationFilter
from django.core.management import call_command

from .models import NotificationModel, NotificationStatus
from .tables import NotificationTable

class IndexView(TpLoginRequiredMixin, RedirectView):
    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):
    template_name = 'home/dashboard.html'

    total_number_of_devices = 15
    total_number_of_certificates = 18
    total_number_of_issuing_ca = 3
    last_week_dates = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_notifications(self):
        """Fetch notification data for the table."""
        notifications = NotificationModel.objects.all()
        return notifications

    def generate_integer_array(self):
        data = [(i + 1) * 2 for i in range(7)]
        for i in range(1, len(data)):
            data[i] += 1
        return data

    def get_bar_chart_data(self):
        data = [(i % 4 + 1) for i in range(7)]
        return data

    def generate_last_week_dates(self):
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        dates_as_strings = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        return dates_as_strings

    def get_all_devices(self):
        total_number_devices = self.generate_integer_array()
        devices_history = [[total_number_devices[i] - i % 3 if j % 2 else i % 3 for i in range(7)] for j in range(2)]
        return devices_history

    def get_all_endpoints(self):
        devices_history = [[self.total_number_of_certificates - i % 2 if j % 2 else i % 2 for i in range(7)] for j in
                           range(2)]
        return devices_history

    def get_number_of_devices(self):
        # get all devices
        # devices = Device.objects.all() #.count()
        # print(devices.get(device_name="test"))
        # return devices.count()
        return self.total_number_of_devices

    def get_number_of_root_cas(self):
        return 3

    def get_number_of_issuing_cas(self):
        return self.total_number_of_issuing_ca

    def get_number_of_certificates(self):
        return self.total_number_of_certificates

    def get_line_chart_config(self):
        config = {
            "type": "line",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": "Number of Root CAs",
                    "data": self.generate_integer_array(),
                    "borderColor": "#0d6efd",
                    "backgroundColor": "rgba(13.0, 110.0, 253.0, 0.3)",
                    "tension": 0.4,
                    "fill": False
                }]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_bar_chart_ca_config(self):
        config = {
            "type": "bar",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": "Issuing CA1",
                    "data": self.get_bar_chart_data(),
                    "borderColor": "#ffc107",
                    "backgroundColor": "#ffc107",
                    "tension": 0.4,
                    "fill": False,
                    "stack": "stack"
                },
                    {
                        "label": "Issuing CA2",
                        "data": self.get_bar_chart_data(),
                        "borderColor": "#0d6efd",
                        "backgroundColor": "#0d6efd",
                        "fill": False,
                        "stack": "stack"
                    },
                    {
                        "label": "Issuing CA3",
                        "data": self.get_bar_chart_data(),
                        "borderColor": "#d10c15",
                        "backgroundColor": "#d10c15",
                        "fill": False,
                        "stack": "stack"
                    }]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_bar_chart_device_config(self):
        config = {
            "type": "bar",
            "data": {
                "labels": ["oMethod 1", "oMethod 2", "oMethod 3", "oMethod 4"],
                "datasets": [{
                    "label": "Number of Devices",
                    "data": self.get_bar_chart_data(),
                    "borderColor": "#0d6efd",
                    "backgroundColor": "#0d6efd",
                    "tension": 0.4,
                    "fill": True
                }]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_bar_chart_cert_config(self):
        config = {
            "type": "bar",
            "data": {
                "labels": ["TLS Server", "TLS Client", "OPC UA Server", "OPC UA Client"],
                "datasets": [{
                    "label": "certificate template",
                    "data": self.get_bar_chart_data(),
                    "borderColor": "#0d6efd",
                    "backgroundColor": "#0d6efd",
                    "tension": 0.4,
                    "fill": True
                }]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_donut_chart_cert_config(self):
        number_of_active_certs = self.get_number_of_certificates()
        domain1 = 2
        domain2 = 3
        domain3 = number_of_active_certs - domain1 - domain2
        config = {
            "type": "doughnut",
            "data": {
                "labels": ["domain 1", "domain 2", "domain 3"],
                "datasets": [{
                    "data": [domain1, domain2, domain3],
                    "borderWidth": 1,
                    "backgroundColor": [
                        '#0d6efd',
                        '#FFC107',
                        '#d10c15'
                    ],
                    "hoverOffset": 4
                }]
            }
        }
        return config

    def get_donut_chart_ca_config(self):
        number_of_issuing_ca = self.get_number_of_issuing_cas()
        remote = 2
        local = 3
        self_gen = number_of_issuing_ca - remote - local
        config = {
            "type": "pie",
            "data": {
                "labels": ["Remote", "Local", "Self-gen"],
                "datasets": [{
                    "data": [remote, local, self_gen],
                    "borderWidth": 1,
                    "backgroundColor": [
                        '#0d6efd',
                        '#FFC107',
                        '#d10c15'
                    ],
                    "hoverOffset": 4
                }]
            }
        }
        return config

    def get_donut_chart_device_config(self):
        number_of_devices = self.get_number_of_devices()
        domain1 = 8
        domain2 = 3
        domain3 = number_of_devices - domain1 - domain2
        config = {
            "type": "doughnut",
            "data": {
                "labels": ["domain 1", "domain 2", "domain 3"],
                "datasets": [{
                    "data": [domain1, domain2, domain3],
                    "borderWidth": 1,
                    "backgroundColor": [
                        '#0d6efd',
                        '#ffc107',
                        '#d10c15'
                    ],
                    "hoverOffset": 4
                }]
            }
        }
        return config

    def line_chart_cert_config(self):
        endpoint_history = self.get_all_endpoints()
        config = {
            "type": "line",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": 'Revoked',
                    "data": endpoint_history[0],
                    "borderColor": "#ffc107",
                    "backgroundColor": "#ffc107",
                    "stack": "stack",
                    "fill": False,
                },
                    {
                        "label": "Active",
                        "data": endpoint_history[1],
                        "borderColor": "#0d6efd",
                        "backgroundColor": "#0d6efd",
                        "fill": False,
                        "stack": "stack"
                    }
                ]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_line_chart_device_config(self):
        device_history = self.get_all_devices()
        config = {
            "type": "line",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": 'Offboarded',
                    "data": device_history[0],
                    "backgroundColor": '#ffc107',
                    "borderColor": "#ffc107",
                    # "stack": "stack"
                },
                    {
                        "label": 'Waiting for onboarding',
                        "data": [x + 1 for x in device_history[0]],
                        "backgroundColor": "#d10c15",
                        "borderColor": "#d10c15",
                        # "stack": "stack"
                    },
                    {
                        "label": "Onboarded",
                        "data": device_history[1],
                        "borderColor": "#0d6efd",
                        "backgroundColor": "#0d6efd",
                        "tension": 0.4,
                        "fill": False,
                        # "stack": "stack"
                    }
                ]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": True
                    }
                }
            }
        }
        return config

    def get_alerts(self):
        messages = ["Test1", "Test2", "Test3"]
        entry_type = "info"
        now = datetime.now()
        formatted_date = now.strftime("%Y-%m-%d")  # Format date as YYYY-MM-DD

        # Create a list of dictionaries with type, message, and date
        alerts = [{
            'type': entry_type,
            'message': message,
            'time': formatted_date
        } for message in messages]

        return alerts

    def get_certs(self):
        names = ["Cert1", "Cert2", "Cert3"]
        now = datetime.now()
        formatted_date = now.strftime("%Y-%m-%d")  # Format date as YYYY-MM-DD

        # Create a list of dictionaries with type, message, and date
        certs = [{
            'cname': name,
            'ica': name,
            'message': 'info',
            'time': formatted_date
        } for name in names]

        return certs

    def get_devices(self):
        names = ["Device1", "Device2", "Device3"]
        now = datetime.now()
        formatted_date = now.strftime("%Y-%m-%d")  # Format date as YYYY-MM-DD

        # Create a list of dictionaries with type, message, and date
        devices = [{
            'device': name,
            'domain': name + "085",
            'domain': "domain-123",
            'message': "onboarded",
            'time': formatted_date
        } for name in names]

        return devices

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # device chart data
        context['line_chart_device_config'] = json.dumps(self.get_line_chart_device_config())
        context['donut_chart_device_config'] = json.dumps(self.get_donut_chart_device_config())
        context['bar_chart_device_config'] = json.dumps(self.get_bar_chart_device_config())

        # cert chart data
        context['line_chart_cert_config'] = json.dumps(self.line_chart_cert_config())
        context['donut_chart_cert_config'] = json.dumps(self.get_donut_chart_cert_config())
        context['bar_chart_cert_config'] = json.dumps(self.get_bar_chart_cert_config())

        # ca chart data
        context['donut_chart_ca_config'] = json.dumps(self.get_donut_chart_ca_config())
        context['bar_chart_ca_config'] = json.dumps(self.get_bar_chart_ca_config())
        context['line_chart_config'] = json.dumps(self.get_line_chart_config())

        context['number_of_devices'] = self.get_number_of_devices()
        context['number_of_issuing_cas'] = self.get_number_of_issuing_cas()
        context['number_of_root_cas'] = self.get_number_of_root_cas()
        context['number_of_certificates'] = self.get_number_of_certificates()
        context['alerts'] = self.get_alerts()
        context['certs'] = self.get_certs()
        context['devices'] = self.get_devices()

        context = self.handle_notifications(context)

        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

    def handle_notifications(self, context):
        all_notifications = NotificationModel.objects.all()

        notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
        filtered_notifications = notification_filter.qs

        all_notifications_table = NotificationTable(filtered_notifications)
        RequestConfig(self.request, paginate={"per_page": 5}).configure(all_notifications_table)

        context['all_notifications_table'] = all_notifications_table
        context['notification_filter'] = notification_filter

        return context

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

    def get(self, request, *args, **kwargs):
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
