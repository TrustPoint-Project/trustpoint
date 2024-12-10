"""This module contains all views concerning the devices application."""
from __future__ import annotations

from django_tables2 import SingleTableView  # type: ignore[import-untyped]
from django.views.generic.edit import CreateView    # type: ignore[import-untyped]
from django.urls import reverse_lazy    # type: ignore[import-untyped]
from django.views.generic.base import RedirectView  # type: ignore[import-untyped]

from trustpoint.views.base import TpLoginRequiredMixin
from core.validator.field import UniqueNameValidator
from devices.models import DeviceModel
from devices.tables import DeviceTable
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from typing import ClassVar


class DevicesRedirectView(TpLoginRequiredMixin, RedirectView):
    """View that redirects to the index of the devices application."""

    permanent = False
    pattern_name = 'devices:devices'


class DeviceContextMixin:
    """Mixin which adds context_data for the Devices -> Devices pages."""

    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'devices'}


class DeviceTableView(DeviceContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Endpoint Profiles List View."""

    model = DeviceModel
    table_class = DeviceTable
    template_name = 'devices/devices.html'
    context_object_name = 'devices'


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    model = DeviceModel
    fields = ['unique_name', 'serial_number', 'domains']
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')

    @staticmethod
    def clean_device_name(device_name: str) -> str:
        UniqueNameValidator(device_name)
        return device_name
