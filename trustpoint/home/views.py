from django.shortcuts import render
from django.views.generic.base import RedirectView, TemplateView

from trustpoint.views import TpLoginRequiredMixin


class IndexView(TpLoginRequiredMixin, RedirectView):
    permanent = True
    pattern_name = 'home:dashboard'


class DashboardView(TpLoginRequiredMixin, TemplateView):

    template_name = 'home/dashboard.html'

    def get_context_data(self, **kwargs):
        kwargs.update({'page_category': 'home', 'page_name': 'dashboard'})
