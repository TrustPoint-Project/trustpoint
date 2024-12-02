from __future__ import annotations

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django_tables2 import SingleTableView
# from pki.forms import (
#     IssuingCaAddFileImportPkcs12Form,
#     IssuingCaAddFileImportSeparateFilesForm,
#     IssuingCaAddMethodSelectForm,
# )
# from pki.models import IssuingCaModel
# from pki.tables import IssuingCaTable
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    TpLoginRequiredMixin,
)


class IssuingCaContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'

#
# class IssuingCaTableView(IssuingCaContextMixin, TpLoginRequiredMixin, SingleTableView):
#     """Issuing CA Table View."""
#
#     model = IssuingCaModel
#     table_class = IssuingCaTable
#     template_name = 'pki/issuing_cas/issuing_cas.html'
#
#
# class IssuingCaAddMethodSelectView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
#     template_name = 'pki/issuing_cas/add/method_select.html'
#     form_class = IssuingCaAddMethodSelectForm
#
#     def form_valid(self, form) -> HttpResponse:
#         method_select = form.cleaned_data.get('method_select')
#         if not method_select:
#             return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))
#
#         if method_select and method_select == 'local_file_import':
#             return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))
#
#         return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))
#
#
# class IssuingCaAddFileImportPkcs12View(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
#
#     template_name = 'pki/issuing_cas/add/file_import.html'
#     form_class = IssuingCaAddFileImportPkcs12Form
#     success_url = reverse_lazy('pki:issuing_cas')
#
#
# class IssuingCaAddFileImportSeparateFilesView(IssuingCaContextMixin, TpLoginRequiredMixin, FormView):
#
#     template_name = 'pki/issuing_cas/add/file_import.html'
#     form_class = IssuingCaAddFileImportSeparateFilesForm
#     success_url = reverse_lazy('pki:issuing_cas')
#
#
# class IssuingCaDetailView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView):
#
#     model = IssuingCaModel
#     success_url = reverse_lazy('pki:issuing_cas')
#     ignore_url = reverse_lazy('pki:issuing_cas')
#     template_name = 'pki/issuing_cas/details.html'
#     context_object_name = 'issuing_ca'
#
# class IssuingCaConfigView(IssuingCaContextMixin, TpLoginRequiredMixin, DetailView, FormView):
#
#     model = IssuingCaModel
#     success_url = reverse_lazy('pki:issuing_cas')
#     ignore_url = reverse_lazy('pki:issuing_cas')
#     template_name = 'pki/issuing_cas/config.html'
#     context_object_name = 'issuing_ca'
#
#     def get_form_kwargs(self):
#         """Pass the instance to the ModelForm."""
#         kwargs = super().get_form_kwargs()
#         kwargs['instance'] = self.get_object()
#         return kwargs
#
#     def get_second_form_kwargs(self):
#         """Pass the instance to the second ModelForm."""
#         return {
#             'instance': self.get_object()
#         }
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         if 'form' not in context:
#             context['form'] = self.get_form(self.get_form_class())
#         return context
#
#     def post(self, request, *args, **kwargs):
#         """Handle the two forms."""
#         form = self.get_form(self.get_form_class())
#
#         if form.is_valid():
#             form.save()
#             messages.success(request, _("Settings updated successfully."))
#             return self.form_valid(form)
#         else:
#             return self.form_invalid(form)
#
# class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, TpLoginRequiredMixin, BulkDeleteView):
#
#     model = IssuingCaModel
#     success_url = reverse_lazy('pki:issuing_cas')
#     ignore_url = reverse_lazy('pki:issuing_cas')
#     template_name = 'pki/issuing_cas/confirm_delete.html'
#     context_object_name = 'issuing_cas'
