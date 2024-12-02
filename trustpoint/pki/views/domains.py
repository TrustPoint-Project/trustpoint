from __future__ import annotations

import enum

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import SingleTableView

from pki.forms import DomainCreateForm, DomainUpdateForm
from pki.models import DomainModel
from pki.tables import DomainTable
from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin


class PkiProtocol(enum.Enum):

    EST = 'est'
    CMP = 'cmp'
    REST = 'rest'
    SCEP = 'scep'
    ACME = 'acme'


class DomainContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'domains'


class DomainTableView(DomainContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Domain Table View."""

    model = DomainModel
    table_class = DomainTable
    template_name = 'pki/domains/domain.html'


class DomainCreateView(DomainContextMixin, TpLoginRequiredMixin, CreateView):

    model = DomainModel
    template_name = 'pki/domains/add.html'
    form_class = DomainCreateForm
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainUpdateView(DomainContextMixin, TpLoginRequiredMixin, UpdateView):

    model = DomainModel
    template_name = 'pki/domains/add.html'
    form_class = DomainUpdateForm
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainConfigView(DomainContextMixin, TpLoginRequiredMixin, DetailView):
    model = DomainModel
    template_name = 'pki/domains/config.html'
    context_object_name = 'domain'
    success_url = reverse_lazy('pki:domains')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = self.get_object()

        context['protocols'] = {
            'cmp': domain.cmp_protocol if hasattr(domain, 'cmp_protocol') else None,
            'est': domain.est_protocol if hasattr(domain, 'est_protocol') else None,
            'acme': domain.acme_protocol if hasattr(domain, 'acme_protocol') else None,
            'scep': domain.scep_protocol if hasattr(domain, 'scep_protocol') else None,
            'rest': domain.rest_protocol if hasattr(domain, 'rest_protocol') else None
        }

        return context

    def post(self, request, *args, **kwargs):
        domain = self.get_object()

        active_protocols = request.POST.getlist('protocols')

        for protocol in PkiProtocol:
            protocol_name = protocol.value
            protocol_object = domain.get_protocol_object(protocol_name)
            if protocol_object is not None:
                protocol_object.status = protocol_name in active_protocols
                protocol_object.save()

        messages.success(request, _("Settings updated successfully."))
        return HttpResponseRedirect(self.success_url)


class DomainDetailView(DomainContextMixin, TpLoginRequiredMixin, DetailView):

    model = DomainModel
    template_name = 'pki/domains/details.html'
    context_object_name = 'domain'
