from __future__ import annotations

from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView  # type: ignore[import-untyped]
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

class IssuingCaTableView(ListView):
    """Issuing CA Table View."""

    model = IssuingCaModel
    template_name = 'pki/issuing_cas/issuing_cas.html'  # Template file
    context_object_name = 'issuing-ca'
    paginate_by = 5  # Number of items per page

    def get_queryset(self):
        queryset = IssuingCaModel.objects.all()

        # Get sort parameter (e.g., "name" or "-name")
        sort_param = self.request.GET.get("sort", "unique_name")  # Default to "unique_name"
        return queryset.order_by(sort_param)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get current sorting column
        sort_param = self.request.GET.get("sort", "unique_name")  # Default to "unique_name"
        is_desc = sort_param.startswith("-")  # Check if sorting is descending
        current_sort = sort_param.lstrip("-")  # Remove "-" to get column name
        next_sort = f"-{current_sort}" if not is_desc else current_sort  # Toggle sorting

        # Pass sorting details to the template
        context.update({
            "current_sort": current_sort,
            "is_desc": is_desc,
        })
        return context


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

    http_method_names = ['get']

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
