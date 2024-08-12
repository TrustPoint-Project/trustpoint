from __future__ import annotations

from django.urls import reverse_lazy

from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import SingleTableView

from trustpoint.views import BulkDeleteView, ContextDataMixin, TpLoginRequiredMixin

from ..forms import DomainCreateForm, DomainUpdateForm
from ..models import DomainModel

from ..tables import DomainTable


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
