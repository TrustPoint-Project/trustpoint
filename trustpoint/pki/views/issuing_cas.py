from __future__ import annotations

from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy

from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django_tables2 import SingleTableView

from trustpoint.views import BulkDeleteView, ContextDataMixin, TpLoginRequiredMixin

from ..forms import (
    IssuingCaAddFileImportOtherForm,
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddMethodSelectForm,
    IssuingCaFileTypeSelectForm,
)

from ..models import IssuingCaModel

from ..tables import IssuingCaTable


class IssuingCaContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'


class IssuingCaTableView(IssuingCaContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Issuing CA Table View."""

    model = IssuingCaModel
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'


class IssuingCaAddMethodSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
    template_name = 'pki/issuing_cas/add/method_select.html'
    form_class = IssuingCaAddMethodSelectForm

    def form_valid(self, form) -> HttpResponse:
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))

        if method_select and method_select == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))


class IssuingCaAddFileTypeSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
    template_name = 'pki/issuing_cas/add/file_type_select.html'
    form_class = IssuingCaFileTypeSelectForm

    def form_valid(self, form) -> HttpResponse:
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        if method_select == 'pkcs_12':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-pkcs12'))
        elif method_select == 'other':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-other'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))


class IssuingCaAddFileImportPkcs12View(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportPkcs12Form
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaAddFileImportOtherView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportOtherForm
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaDetailView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):
    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'issuing_cas'
