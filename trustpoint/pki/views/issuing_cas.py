from __future__ import annotations

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.utils.translation import gettext as _
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django_tables2 import SingleTableView
from pki.forms import (
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportSeparateFilesForm,
    IssuingCaAddMethodSelectForm,
)
from pki.models import IssuingCaModel
from pki.tables import IssuingCaTable
from trustpoint.views.base import (
    LoggerMixin,
    BulkDeleteView,
    ContextDataMixin,
    TpLoginRequiredMixin,
)


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


class IssuingCaAddFileImportPkcs12View(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportPkcs12Form
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaAddFileImportSeparateFilesView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportSeparateFilesForm
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaDetailView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ('get', )

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'



class IssuingCaConfigView(LoggerMixin, IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/config.html'
    context_object_name = 'issuing_ca'


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'issuing_cas'


class IssuingCaCrlGenerationView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/crl_generation.html'
    context_object_name = 'issuing_ca'

    http_method_names = ('get', 'post')

    def get(self, request, *args, **kwargs) -> HttpResponse: # TODO: POST
        issuing_ca = self.get_object()
        if issuing_ca.issue_crl():
            messages.success(request, _('CRL for Issuing CA %s has been generated.') % issuing_ca.unique_name)
        else:
            messages.error(request, _('Failed to generate CRL for Issuing CA %s.') % issuing_ca.unique_name)
        return redirect('pki:issuing_cas-config', pk=issuing_ca.id)


class CrlDownloadView(IssuingCaContextMixin, DetailView):

    http_method_names = ('get', )

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    context_object_name = 'issuing_ca'

    def get(self, request, *args, **kwargs) -> HttpResponse:
        issuing_ca = self.get_object()
        crl_pem = issuing_ca.crl_pem
        if not crl_pem:
            messages.warning(request, _('No CRL available for issuing CA %s.') % issuing_ca.unique_name)
            return redirect('pki:issuing_cas')
        response = HttpResponse(crl_pem, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{issuing_ca.unique_name}.crl"'
        return response
