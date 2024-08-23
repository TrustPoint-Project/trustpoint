from __future__ import annotations

from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django_tables2 import SingleTableView
from sysconf.security import SecurityFeatures
from sysconf.views import SecurityLevelMixin

from pki.forms import (
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportSeparateFilesForm,
    IssuingCaAddMethodSelectForm,
)
from pki.models import IssuingCaModel
from pki.tables import IssuingCaTable
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    PrimaryKeyFromUrlToQuerysetMixin,
    TpLoginRequiredMixin,
)


class IssuingCaContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'

# @TODO: Remove Security Level Restriction from IssuingCaTableView. Only for demo purpose
class IssuingCaTableView(SecurityLevelMixin, IssuingCaContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Issuing CA Table View."""

    model = IssuingCaModel
    table_class = IssuingCaTable
    template_name = 'pki/issuing_cas/issuing_cas.html'
    security_feature = SecurityFeatures.ISSUING_CA_TABLE_VIEW
    no_permisson_url = '/home/dashboard/'

    def __init__(self, *args, **kwargs):
        super().__init__(security_feature=self.security_feature, no_permisson_url=self.no_permisson_url, *args, **kwargs)


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
