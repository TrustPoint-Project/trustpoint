import random, json
from django.shortcuts import render
from django.views.generic.base import RedirectView, TemplateView
from datetime import datetime, timedelta

from trustpoint.views import TpLoginRequiredMixin


class IndexView(TpLoginRequiredMixin, RedirectView):

    permanent = False
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):

    template_name = 'home/dashboard.html'

    def get_line_chart_data(self):
        # Generate random data for the line chart
        data = [random.randint(0, 100) for _ in range(7)]
        return data

    def generate_last_week_dates(self):
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        dates_as_strings = [(start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        return dates_as_strings 

    def get_number_of_devices(self):
        return 50
    def get_line_chart_config(self):
        config = {
            "type": "line",
            "data": {
                "labels": self.generate_last_week_dates(),
                "datasets": [{
                    "label": "Number of devices",
                    "data": self.get_line_chart_data(),
                    "borderColor": "rgb(75, 192, 192)",
                    "backgroundColor": "rgba(75, 192, 192, 0.2)",
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
                "labels": self.generate_last_week_dates(),
                "datasets": [{
                    "label": "Number of keys",
                    "data": self.get_line_chart_data(),
                    "borderColor": "rgb(75, 192, 192)",
                    "backgroundColor": "rgba(75, 192, 192, 0.2)",
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
    
    def get_donut_chart_config(self):
        config = {
      "type": "doughnut",
      "data": {
        "labels": ["active", "inactive"],
        "datasets": [{
          "data": [22, 38],
          "borderWidth": 1,
          "backgroundColor": [
            '#D10C15',
            '#F19100'
          ],
          "hoverOffset": 4
        }]
      }
    }
        return config
    
    def get_stack_chart_config(self):
        config = {
            "type": "bar",
            "data": {
                "labels": self.generate_last_week_dates(),
                "datasets": [{
                    "label": "Active",
                    "data": self.get_line_chart_data(),
                    "borderColor": "rgb(75, 192, 192)",
                    "backgroundColor": "rgba(75, 192, 192, 0.2)",
                    "tension": 0.4,
                    "fill": True,
                    "stack": "stack"
                  },
                  {
                    "label": 'Inactive',
                    "data": self.get_line_chart_data(),
                    "backgroundColor": [
                      '#D10C15',
                    ],
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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        line_chart_config = self.get_line_chart_config()
        context['line_chart_config'] = json.dumps(line_chart_config)
        context['bar_chart_config'] = json.dumps(self.get_bar_chart_config())
        context['stack_chart_config'] = json.dumps(self.get_stack_chart_config())
        context['donut_chart_config'] = json.dumps(self.get_donut_chart_config())
        context['number_of_devices'] = self.get_number_of_devices()
        context['page_category'] = 'home'
        context['page_name'] = 'dashboard'
        return context

