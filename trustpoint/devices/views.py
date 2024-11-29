from __future__ import annotations

from django_tables2 import SingleTableView
from django.views.generic.edit import CreateView
from django.urls import reverse_lazy

from trustpoint.views.base import ContextDataMixin, TpLoginRequiredMixin
from devices.models import DeviceModel
from devices.tables import DeviceTable
from pki.validator.field import UniqueNameValidator


class DeviceContextMixin(TpLoginRequiredMixin, ContextDataMixin):
    """Mixin which adds context_data for the Devices -> Devices pages."""

    context_page_category = 'devices'
    context_page_name = 'devices'


class DeviceListView(DeviceContextMixin, TpLoginRequiredMixin, SingleTableView):
    """Endpoint Profiles List View."""

    model = DeviceModel
    table_class = DeviceTable
    template_name = 'devices/devices.html'


class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    model = DeviceModel
    fields = ['unique_name', 'serial_number', 'primary_domain']
    template_name = 'devices/add.html'
    success_url = reverse_lazy('devices:devices')

    def clean_device_name(self, device_name) -> str:
        UniqueNameValidator(device_name)
        return device_name
