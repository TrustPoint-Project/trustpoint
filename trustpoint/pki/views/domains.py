from __future__ import annotations

from devices.models import Device
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import RequestConfig, SingleTableView

from pki.forms import DomainCreateForm, DomainUpdateForm
from pki.models import DomainModel, TrustStoreModel
from pki.tables import DomainTable, ProtocolConfigTable, TrustStoreConfigFromDomainTable
from trustpoint.views.base import BulkDeleteView, ContextDataMixin, TpLoginRequiredMixin


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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        protocol_table = ProtocolConfigTable(self.get_protocol_data())
        RequestConfig(self.request).configure(protocol_table)
        context['protocol_table'] = protocol_table

        trust_store_table = TrustStoreConfigFromDomainTable(self.get_trust_store_data())
        RequestConfig(self.request).configure(trust_store_table)
        context['trust_store_table'] = trust_store_table
        devices_count = Device.count_devices_by_domain_and_status(domain=self.get_object())
        context['devices_count'] = {item['device_onboarding_status']: item['count'] for item in devices_count}

        return context

    def get_protocol_data(self):
        # @TODO Demo data, replace with real data
        return [
            {'protocol': 'EST', 'status': 'Enabled', 'operation': 'All', 'action': 'Disable', 'url_path': '/.well-known/est/my-default-domain'},
            {'protocol': 'Lightweight CMP', 'status': 'Enabled', 'operation': 'Limited', 'action': 'Disable', 'url_path': '/.well-known/cmp/p/my-default-domain'},
            {'protocol': 'SCEP', 'status': 'Disabled', 'operation': '-', 'action': 'Enable', 'url_path': ''},
            {'protocol': 'ACME', 'status': 'Disabled', 'operation': '-', 'action': 'Enable', 'url_path': ''},
            {'protocol': 'REST', 'status': 'Enabled', 'operation': 'All', 'action': 'Disable', 'url_path': '/pki/rest/my-default-domain'},
        ]

    def get_trust_store_data(self):
        # @TODO Demo data, replace with real data
        return [
            {'unique_name': 'Issuing CA 1 Trust Store', 'url_path': 'issuing-ca-1-trust-store'},
            {'unique_name': 'Intranet Generic TLS Server Trust Store', 'url_path': 'intranet-generic-tls-server-trust-store'},
            {'unique_name': 'Intranet Monitoring Rest Api Trust Store', 'url_path': 'intranet-monitoring-rest-api-trust-store'},
        ]


class DomainDetailView(DomainContextMixin, TpLoginRequiredMixin, DetailView):

    model = DomainModel
    template_name = 'pki/domains/details.html'
    context_object_name = 'domain'


class DomainBulkDeleteConfirmView(DomainContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = DomainModel
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')
    template_name = 'pki/domains/confirm_delete.html'
    context_object_name = 'domains'
