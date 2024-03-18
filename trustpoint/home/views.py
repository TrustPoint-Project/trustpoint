import random, json
from django.shortcuts import render
from django.views.generic.base import RedirectView, TemplateView
from datetime import datetime, timedelta

from trustpoint.views import TpLoginRequiredMixin


class IndexView(TpLoginRequiredMixin, RedirectView):
    permanent = True
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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        line_chart_config = self.get_line_chart_config()
        context['line_chart_config'] = json.dumps(line_chart_config)
        context['number_of_devices'] = self.get_number_of_devices()
        return context
