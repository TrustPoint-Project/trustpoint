"""Contains views specific to the devices application."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView
from django.views.generic.list import BaseListView, MultipleObjectTemplateResponseMixin
from django_filters.views import FilterView
from django_tables2 import SingleTableView
from pki.models import DomainModel
from pki.validator.field import UniqueNameValidator

from devices.forms import DeviceConfigForm, DomainSelectionForm
from trustpoint.views.base import BulkDeletionMixin, ContextDataMixin, TpLoginRequiredMixin

from .filters import DeviceFilter
from .models import Device
from .tables import DeviceTable

if TYPE_CHECKING:
    from typing import Any

    from django.db.models import QuerySet
    from django.http import HttpResponse

log = logging.getLogger('tp.devices')

class DeviceContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the Devices -> Devices pages."""

    context_page_category = 'devices'
    context_page_name = 'devices'


class DeviceListView(DeviceContextMixin, TpLoginRequiredMixin, FilterView, SingleTableView):
    """Endpoint Profiles List View."""

    model = Device
    table_class = DeviceTable
    template_name = 'devices/devices.html'

    filterset_class = DeviceFilter


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    model = Device
    fields = ['device_name', 'domains', 'tags']  # noqa: RUF012
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')

    def clean_device_name(self, device_name: str) -> str:
        """Validates and cleans the device name.

        Args:
            device_name (str): The name of the device to validate.

        Returns:
            str: The cleaned device name.
        """
        UniqueNameValidator(device_name)
        return device_name


class ConfigDeviceView(DeviceContextMixin, TpLoginRequiredMixin, UpdateView):
    """Device Config View."""
    model = Device
    template_name = 'devices/config/config.html'
    success_url = reverse_lazy('devices:devices')
    form_class = DeviceConfigForm

    def dispatch(self, request, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        self.object = self.get_object()
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs) -> dict:  # noqa: ANN003
        """Adds domains and additional actions to the context."""
        context = super().get_context_data(**kwargs)
        device = self.get_object()

        context['domains'] = device.domains.all()
        context['add_domains_url'] = reverse('devices:add_domains', kwargs={'pk': device.pk})
        return context

    def post(self, request, *args, **kwargs): # noqa: ANN001, ANN002, ANN003
        """Handle POST requests to update device configuration or manage domains."""
        device: Device = self.get_object()

        if 'delete_domain' in request.POST:
            domain_id = request.POST.get('delete_domain')
            try:
                domain = device.get_domain(domain_id)
                device.domains.remove(domain)
                messages.success(request, _('Domain %s successfully removed.') % domain)
            except DomainModel.DoesNotExist:
                messages.error(request, _('The domain does not exist or is not associated with this device.'))
            return redirect(self.get_success_url())

        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, form):
        """Handle valid form submission."""
        try:
            device = self.get_object()
            device.device_serial_number = form.cleaned_data.get('device_serial_number', device.device_serial_number)
            device.save()

            messages.success(self.request, _('Device configuration updated successfully.'))
            return redirect(self.get_success_url())
        except Exception as e:
            log.exception(f'Error while saving device configuration: {e}')
            messages.error(self.request, _('There was an error updating the device configuration.'))
            return self.form_invalid(form)

    def get_success_url(self):
        """Redirect back to the configuration page of the current device."""
        return reverse('devices:devices-config', kwargs={'pk': self.object.pk})


class AddDomainsView(DeviceContextMixin, TpLoginRequiredMixin, UpdateView):
    """View to add domains to a device."""
    model = Device
    form_class = DomainSelectionForm
    template_name = 'devices/config/add_domains.html'

    def dispatch(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super().dispatch(request, *args, **kwargs)

    def get_form(self, form_class=None):
        """Override the form to show only unassociated domains."""
        form_class = form_class or self.form_class
        device = self.get_object()

        available_domains = DomainModel.objects.exclude(id__in=device.domains.values_list('id', flat=True))

        form = form_class()
        form.fields['domains'].queryset = available_domains
        return form

    def get_context_data(self, **kwargs):
        """Add information about the available domains to the context."""
        context = super().get_context_data(**kwargs)
        device = self.get_object()

        # Get the available domains
        available_domains = DomainModel.objects.exclude(id__in=device.domains.values_list('id', flat=True))

        # Add a flag to indicate if there are no domains available
        if not available_domains.exists():
            context['no_domains_available'] = True
        return context

    def get_success_url(self):
        """Redirect back to the configuration page of the current device."""
        return reverse('devices:devices-config', kwargs={'pk': self.object.pk})

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        form = self.form_class(request.POST)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def form_valid(self, form):
        """Add selected domains to the device."""
        device = self.get_object()
        selected_domains = form.cleaned_data['domains']
        device.domains.add(*selected_domains)
        messages.success(self.request, _('Domains successfully added.'))
        return redirect(self.get_success_url())

    def form_invalid(self, form):
        """Handle invalid form submission."""
        messages.error(self.request, _('There was an error updating the domains.'))
        return self.render_to_response(self.get_context_data(form=form))


class DeviceDetailView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):
    """Detail view for Devices."""

    model = Device
    pk_url_kwarg = 'pk'
    template_name = 'devices/details.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds additional context data for the device detail view.

        Args:
            **kwargs (Any): Additional keyword arguments.

        Returns:
            dict[str, Any]: The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        device: Device = self.get_object()

        context['onboarding_button'] = device.render_onboarding_action()
        certs_by_domain = {}
        if device.domains.exists():
            for domain in device.domains.all():
                domain_certs = device.get_all_active_certs_by_domain(domain)
                if domain_certs:
                    certs_by_domain[domain] = {
                        'ldevids': domain_certs['ldevids'],
                        'other': domain_certs['other'],
                    }

            context['certs_by_domain'] = certs_by_domain
        else:
            msg = f'Didn not find any domains for device {device}.'
            raise ValueError(msg)

        return context


class DevicesBulkDeleteView(
    DeviceContextMixin,
    MultipleObjectTemplateResponseMixin,
    BulkDeletionMixin,
    TpLoginRequiredMixin,
    BaseListView,
):
    """View that allows bulk deletion of Devices.

    This view expects a path variable pks containing string with all primary keys separated by forward slashes /.
    It cannot start with a forward slash, however a trailing forward slash is optional.
    If one or more primary keys do not have a corresponding object in the database, the user will be redirected
    to the ignore_url.
    """

    model = Device
    success_url = reverse_lazy('devices:devices')
    ignore_url = reverse_lazy('devices:devices')
    template_name = 'devices/confirm_delete.html'
    context_object_name = 'objects'

    def get_ignore_url(self: DevicesBulkDeleteView) -> str:
        """Gets the get the configured ignore_url.

        If no ignore_url is configured, it will return the success_url.

        Returns:
            str:
                The ignore_url or success_url.

        """
        if self.ignore_url is not None:
            return str(self.ignore_url)
        return str(self.success_url)

    def get_pks(self: DevicesBulkDeleteView) -> list[str]:
        """Gets the primary keys for the objects to delete.

        Expects a string containing the primary keys delimited by forward slashes.
        Cannot start with a forward slash.
        A trailing forward slash is optional.

        Returns:
            list[str]:
                A list of the primary keys as strings.
        """
        return self.kwargs['pks'].split('/')

    def get_queryset(self: DevicesBulkDeleteView) -> QuerySet:
        """Retrieve the queryset of devices to delete.

        Checks if all primary keys correspond to existing objects in the database.
        If not, an empty QuerySet is returned.

        Returns:
            QuerySet: The queryset of devices to delete, or an empty QuerySet if validation fails.
        """
        pks = self.get_pks()
        if not pks:
            return self.model.objects.none()
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            return self.model.objects.none()

        self.queryset = queryset
        return queryset


    def get(self: DevicesBulkDeleteView, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles HTTP GET requests.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            HttpResponse:
                The response corresponding to the HTTP GET request.
        """
        if self.get_queryset() is None:
            return redirect(self.get_ignore_url())

        return super().get(*args, **kwargs)
