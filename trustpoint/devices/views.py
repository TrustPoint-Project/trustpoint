"""Contains views specific to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, FormMixin, UpdateView
from django.views.generic.list import BaseListView, MultipleObjectTemplateResponseMixin
from django_tables2 import SingleTableView

from trustpoint.views.base import BulkDeletionMixin, ContextDataMixin, TpLoginRequiredMixin

from .models import Device
from .tables import DeviceTable

if TYPE_CHECKING:
    from typing import Any

    from django.db.models import QuerySet
    from django.http import HttpResponse


class DeviceContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the Devices -> Devices pages."""

    context_page_category = 'devices'
    context_page_name = 'devices'


class DeviceListView(DeviceContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Endpoint Profiles List View."""

    model = Device
    table_class = DeviceTable
    template_name = 'devices/devices.html'


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    model = Device
    fields = ['device_name', 'onboarding_protocol', 'domain']  # noqa: RUF012
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')


class EditDeviceView(DeviceContextMixin, TpLoginRequiredMixin, UpdateView):
    """Device Edit View."""

    model = Device
    fields = ['device_name', 'onboarding_protocol', 'domain']  # noqa: RUF012
    template_name = 'devices/edit.html'
    success_url = reverse_lazy('devices:devices')


class DeviceDetailView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):
    """Detail view for Devices."""

    model = Device
    pk_url_kwarg = 'pk'
    template_name = 'devices/details.html'


class DevicesBulkDeleteView(
    DeviceContextMixin,
    MultipleObjectTemplateResponseMixin,
    BulkDeletionMixin,
    TpLoginRequiredMixin,
    BaseListView,
):
    """View that allows bulk deletion of Endpoint Profiles.

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

    def get_queryset(self: DevicesBulkDeleteView, *args: Any, **kwargs: Any) -> QuerySet | None:  # noqa: ARG002
        """Gets the queryset of the objects to be deleted.

        Args:
            *args (list):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).
            **kwargs (dict):
                For compatibility. Not used internally in this method. Passed to super().get(*args, **kwargs).

        Returns:
            QuerySet | None:
                The queryset of the objects to be deleted.
                None, if one or more primary keys do not have corresponding objects in the database or
                if the primary key list pks is empty.
        """
        pks = self.get_pks()
        if not pks:
            return None
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

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
