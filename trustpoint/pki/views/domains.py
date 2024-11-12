from __future__ import annotations

import enum

from devices import DeviceOnboardingStatus
from devices.models import Device
from django.contrib import messages
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import RequestConfig, SingleTableView

from pki import ReasonCode
from pki.forms import CMPForm, DomainCreateForm, DomainUpdateForm, ESTForm
from pki.models import DomainModel, IssuedDeviceCertificateModel, TrustStoreModel
from pki.tables import DomainTable, TrustStoreConfigFromDomainTable
from trustpoint.views.base import BulkDeleteView, ContextDataMixin, TpLoginRequiredMixin


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

        trust_store_table = TrustStoreConfigFromDomainTable(TrustStoreModel.objects.all())
        RequestConfig(self.request).configure(trust_store_table)
        context['trust_store_table'] = trust_store_table

        devices_count = Device.count_devices_by_domain_and_status(domain=domain)
        context['devices_count'] = {item['device_onboarding_status']: item['count'] for item in devices_count}

        return context

    def post(self, request, *args, **kwargs):
        domain = self.get_object()

        if 'protocol' in request.POST:
            protocol_name = request.POST.get('protocol')
            if protocol_name == 'cmp':
                cmp_protocol = domain.cmp_protocol
                form = CMPForm(request.POST, instance=cmp_protocol)
            elif protocol_name == 'est':
                est_protocol = domain.est_protocol
                form = ESTForm(request.POST, instance=est_protocol)
            else:
                return JsonResponse({'success': False, 'error': 'Unknown protocol'})

            if form.is_valid():
                form.save()

        selected_truststore_ids = request.POST.getlist('truststores')
        selected_truststores = TrustStoreModel.objects.filter(pk__in=selected_truststore_ids)
        domain.truststores.set(selected_truststores)

        active_protocols = request.POST.getlist('protocols')

        for protocol in PkiProtocol:
            protocol_name = protocol.value
            protocol_object = domain.get_protocol_object(protocol_name)
            if protocol_object is not None:
                protocol_object.status = protocol_name in active_protocols
                protocol_object.save()

        messages.success(request, _("Settings updated successfully."))
        return self.get(request, *args, **kwargs)

    def get_protocol_form(self, protocol_name):
        """Returns the form instance for a given protocol."""
        domain = self.get_object()
        if protocol_name == 'cmp':
            return CMPForm(instance=domain.cmp_protocol)
        elif protocol_name == 'est':
            return ESTForm(instance=domain.est_protocol)
        return None

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


    @transaction.atomic
    def post(self, *args, **kwargs):
        for domain_id in kwargs:
            domain = DomainModel.objects.get(pk=self.kwargs.get(domain_id))
            query_sets = IssuedDeviceCertificateModel.objects.filter(domain=domain)

            for query_set in query_sets:
                query_set.certificate.revoke(ReasonCode.CESSATION)
                query_set.device.device_onboarding_status = DeviceOnboardingStatus.REVOKED
                query_set.device.save()
        return super().post(*args, **kwargs)


class ProtocolConfigView(DomainContextMixin, View):
    template_name = 'pki/domains/protocol_config_form.html'

    def get(self, request, protocol_name, *args, **kwargs):
        domain = DomainModel.objects.get(pk=self.kwargs.get('domain_id'))
        form = None

        if protocol_name == "cmp":
            cmp_protocol = domain.get_protocol_object('cmp')
            initial_data = {'operation_modes': cmp_protocol.get_operation_list()}
            form = CMPForm(instance=cmp_protocol, initial=initial_data)
        elif protocol_name == "est":
            est_protocol = domain.get_protocol_object('est')
            initial_data = {'operation_modes': est_protocol.get_operation_list()}
            form = ESTForm(instance=est_protocol, initial=initial_data)

        if form:
            form_html = render_to_string(self.template_name, {
                'form': form,
                'protocol_name': protocol_name
            })
            return HttpResponse(form_html)
        else:
            return HttpResponse('<p>Invalid protocol name</p>', status=400)
