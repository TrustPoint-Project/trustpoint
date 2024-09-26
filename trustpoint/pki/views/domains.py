from __future__ import annotations

from devices.models import Device
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import RequestConfig, SingleTableView

from pki.forms import DomainCreateForm, DomainUpdateForm
from pki.models import DomainModel, TrustStoreModel
from pki.pki.request import Protocols
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
        domain = self.get_object()

        context['cmp_protocol'] = domain.cmp_protocol if hasattr(domain, 'cmp_protocol') else None
        context['est_protocol'] = domain.est_protocol if hasattr(domain, 'est_protocol') else None
        context['acme_protocol'] = domain.acme_protocol if hasattr(domain, 'acme_protocol') else None
        context['scep_protocol'] = domain.scep_protocol if hasattr(domain, 'scep_protocol') else None
        context['rest_protocol'] = domain.rest_protocol if hasattr(domain, 'rest_protocol') else None

        context['protocols'] = {
            'cmp': context['cmp_protocol'],
            'est': context['est_protocol'],
            'acme': context['acme_protocol'],
            'scep': context['scep_protocol'],
            'rest': context['rest_protocol']
        }

        trust_store_table = TrustStoreConfigFromDomainTable(TrustStoreModel.objects.all())
        RequestConfig(self.request).configure(trust_store_table)
        context['trust_store_table'] = trust_store_table
        devices_count = Device.count_devices_by_domain_and_status(domain=domain)
        context['devices_count'] = {item['device_onboarding_status']: item['count'] for item in devices_count}

        return context

    def post(self, request, *args, **kwargs):
        domain = self.get_object()
        selected_truststore_ids = request.POST.getlist('truststores')
        selected_truststores = TrustStoreModel.objects.filter(pk__in=selected_truststore_ids)
        domain.truststores.set(selected_truststores)

        active_protocols = request.POST.getlist('protocols')

        for protocol in Protocols:
            protocol_name = protocol.value
            if protocol_name == 'cmp':
                cmp_object = domain.get_cmp_object()
                cmp_object.status = protocol_name in active_protocols
                cmp_object.save()

            # elif protocol_name == 'est':
            #     est_object = domain.get_est_object()
            #     est_object.status = protocol_name in active_protocols
            #     est_object.save()

            # elif protocol_name == 'acme':
            #     acme_object = domain.get_acme_object()
            #     acme_object.status = protocol_name in active_protocols
            #     acme_object.save()

            # elif protocol_name == 'scep':
            #     scep_object = domain.get_scep_object()
            #     scep_object.status = protocol_name in active_protocols
            #     scep_object.save()

            # elif protocol_name == 'rest':
            #     rest_object = domain.get_rest_object()
            #     rest_object.status = protocol_name in active_protocols
            #     rest_object.save()

        return self.get(request, *args, **kwargs)

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
