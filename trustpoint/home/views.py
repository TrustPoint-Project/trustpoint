import json
from django.views.generic.base import RedirectView, TemplateView
from datetime import datetime, timedelta

from trustpoint.views.base import TpLoginRequiredMixin


class IndexView(TpLoginRequiredMixin, RedirectView):

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):

    template_name = 'home/dashboard.html'

    total_number_of_devices = 15
    total_number_of_endpoints = 4
    last_week_dates = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_week_dates = self.generate_last_week_dates()

    def get_line_chart_data(self):
        data = [(i+1)*2 for i in range(7)]
        for i in range(1, len(data)):
          data[i] += 1
        return data
    
    def get_bar_chart_data(self):
        data = [(i%4+1) for i in range(7)]
        return data

    def generate_last_week_dates(self):
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        dates_as_strings = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        return dates_as_strings 
    
    def get_all_devices(self):
        total_number_devices = self.get_line_chart_data()
        devices_history = [[total_number_devices[i]-i%3 if j%2 else i%3 for i in range(7)] for j in range(2)]
        return devices_history

    def get_all_endpoints(self):
        devices_history = [[self.total_number_of_endpoints-i%2 if j%2 else i%2 for i in range(7)] for j in range(2)]
        return devices_history

    def get_number_of_devices(self):
        # get all devices
        # devices = Device.objects.all() #.count()
        # print(devices.get(device_name="test"))
        # return devices.count()
        return self.total_number_of_devices


    def get_number_of_rootcas(self):
        return 2
    def get_number_of_issuingcas(self):
        return 3
    def get_number_of_endpoints(self):
        return self.total_number_of_endpoints
    def get_line_chart_config(self):
        config = {
            "type": "line",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": "Number of devices",
                    "data": self.get_line_chart_data(),
                    "borderColor": "#0d6efd",
                    "backgroundColor": "rgba(13.0, 110.0, 253.0, 0.3)",
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
    def get_bar_chart_config(self):
        config = {
            "type": "bar",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [{
                    "label": "Number of Issuing CAs",
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
    
    def get_endoint_donut_chart_config(self):
        number_of_endpoints = self.get_number_of_endpoints()
        active_endpoints = 3
        config = {
          "type": "doughnut",
          "data": {
            "labels": ["active", "inactive"],
            "datasets": [{
              "data": [active_endpoints, number_of_endpoints-active_endpoints],
              "borderWidth": 1,
              "backgroundColor": [
                '#0d6efd',
                '#D10C15',
              ],
              "hoverOffset": 4
            }]
          }
        }
        return config

    def get_donut_chart_config(self):
        number_of_devices = self.get_number_of_devices()
        active_devices = 8
        config = {
          "type": "doughnut",
          "data": {
            "labels": ["active", "inactive"],
            "datasets": [{
              "data": [active_devices, number_of_devices-active_devices],
              "borderWidth": 1,
              "backgroundColor": [
                '#0d6efd',
                '#D10C15',
              ],
              "hoverOffset": 4
            }]
          }
        }
        return config

    def get_stack_area_chart_config(self):
        endpoint_history = self.get_all_endpoints()
        config = {
            "type": "bar",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [ {
                    "label": 'Inactive',
                    "data": endpoint_history[0],
                    "backgroundColor": [
                      '#D10C15',
                    ],
                    "stack": "stack",
                    "fill": True,
                    },
                    {
                    "label": "Active",
                    "data": endpoint_history[1],
                    "borderColor": "#0d6efd",
                    "backgroundColor": "#0d6efd",
                    "tension": 0.4,
                    "fill": True,
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
    
    def get_stack_chart_config(self):
        device_history = self.get_all_devices()
        config = {
            "type": "bar",
            "data": {
                "labels": self.last_week_dates,
                "datasets": [ {
                    "label": 'Inactive',
                    "data": device_history[0],
                    "backgroundColor": [
                      '#D10C15',
                    ],
                    "stack": "stack"
                    },
                    {
                    "label": "Active",
                    "data": device_history[1],
                    "borderColor": "#0d6efd",
                    "backgroundColor": "#0d6efd",
                    "tension": 0.4,
                    "fill": True,
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
          'name': name,
          'cname': name,
          'valid': formatted_date
      } for name in names]

      return certs

    def get_devices(self):
      names = ["Device1", "Device2", "Device3"]

      # Create a list of dictionaries with type, message, and date
      devices = [{
          'name': name,
          'serial': name+"085",
          'domain': "domain-123",
          'status': "onboarded"
      } for name in names]

      return devices

    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        line_chart_config = self.get_line_chart_config()
        context['line_chart_config'] = json.dumps(line_chart_config)
        context['bar_chart_config'] = json.dumps(self.get_bar_chart_config())
        context['stack_chart_config'] = json.dumps(self.get_stack_chart_config())
        context['stack_area_chart_config'] = json.dumps(self.get_stack_area_chart_config())
        context['donut_chart_config'] = json.dumps(self.get_donut_chart_config())
        context['endpoint_donut_chart_config'] = json.dumps(self.get_endoint_donut_chart_config())
        context['number_of_devices'] = self.get_number_of_devices()
        context['number_of_issuing_cas'] = self.get_number_of_issuingcas()
        context['number_of_root_cas'] = self.get_number_of_rootcas()
        context['number_of_endpoints'] = self.get_number_of_endpoints()
        context['alerts'] = json.dumps(self.get_alerts())
        context['certs'] = json.dumps(self.get_certs())
        context['devices'] = json.dumps(self.get_devices())
        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

