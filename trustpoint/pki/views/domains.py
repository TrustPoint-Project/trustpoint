from __future__ import annotations

import enum
from typing import Any, cast

from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest, Http404
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView, UpdateView
from django_tables2 import SingleTableView, RequestConfig
from django.views.generic.edit import FormView
from pki.forms import DevIdRegistrationForm
from pki.models import DomainModel, DevIdRegistration
from pki.tables import DomainTable, DevIdRegistrationTable
from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin, BulkDeleteView


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


class DomainTableView(ListView):
      model = DomainModel
      template_name = 'pki/domains/domain.html'  # Template file
      context_object_name = 'domain-new'
      paginate_by = 5  # Number of items per page

      def get_queryset(self):
          queryset = DomainModel.objects.all()
          # Get sort parameter (e.g., "name" or "-name")
          sort_param = self.request.GET.get("sort", "unique_name")  # Default to "common_name"
          return queryset.order_by(sort_param)

      def get_context_data(self, **kwargs):
          context = super().get_context_data(**kwargs)

          # Get current sorting column
          sort_param = self.request.GET.get("sort", "unique_name")  # Default to "common_name"
          is_desc = sort_param.startswith("-")  # Check if sorting is descending
          current_sort = sort_param.lstrip("-")  # Remove "-" to get column name
          next_sort = f"-{current_sort}" if not is_desc else current_sort  # Toggle sorting

          # Pass sorting details to the template
          context.update({
              "current_sort": current_sort,
              "is_desc": is_desc,
          })
          return context


class DomainCreateView(DomainContextMixin, TpLoginRequiredMixin, CreateView):

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')


class DomainUpdateView(DomainContextMixin, TpLoginRequiredMixin, UpdateView):

    model = DomainModel
    fields = '__all__'
    template_name = 'pki/domains/add.html'
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

        patterns = DevIdRegistration.objects.filter(domain=domain)
        table = DevIdRegistrationTable(patterns)
        RequestConfig(self.request, paginate={"per_page": 10}).configure(table)
        context['devid_table'] = table


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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = self.get_object()

        patterns = DevIdRegistration.objects.filter(domain=domain)
        table = DevIdRegistrationTable(patterns)
        RequestConfig(self.request, paginate={"per_page": 10}).configure(table)
        context['devid_table'] = table

        return context


class DomainCaBulkDeleteConfirmView(DomainContextMixin, TpLoginRequiredMixin, BulkDeleteView):

    model = DomainModel
    success_url = reverse_lazy('pki:domains')
    ignore_url = reverse_lazy('pki:domains')
    template_name = 'pki/domains/confirm_delete.html'
    context_object_name = 'domains'


class DevIdRegistrationCreateView(FormView):
    """View to create a new DevID Registration."""

    http_method_names = ('get', 'post')

    template_name = 'pki/devid_registration/add.html'
    form_class = DevIdRegistrationForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['domain'] = self.get_domain()
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        domain = self.get_domain()
        initial['domain'] = domain  # Pre-fill the domain field in the form
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        """Provide additional arguments to the form."""
        form_kwargs = super().get_form_kwargs()
        form_kwargs['initial'] = self.get_initial()
        return form_kwargs

    def get_domain(self) -> DomainModel:
        """Fetch the domain based on the primary key passed in the URL."""
        try:
            pk = self.kwargs.get('pk')
            return DomainModel.objects.get(pk=pk)
        except DomainModel.DoesNotExist:
            raise Http404('Domain does not exist.')

    def form_valid(self, form: DevIdRegistrationForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        dev_id_registration = form.save()
        messages.success(
            self.request,
            f'Successfully created DevID Registration: {dev_id_registration.unique_name}',
        )
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the URL to redirect to upon successful form submission."""
        domain = self.get_domain()
        return cast('str', reverse_lazy('pki:domains-config', kwargs={'pk': domain.id}))

class DevIdRegistrationDeleteView(DeleteView):
    """View to delete a DevID Registration."""
    model = DevIdRegistration
    template_name = 'pki/devid_registration/confirm_delete.html'
    success_url = reverse_lazy('pki:domains')

    def delete(self, request, *args, **kwargs):
        """Override delete method to add a success message."""
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('DevID Registration Pattern deleted successfully.'))
        return response
