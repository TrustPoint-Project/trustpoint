"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html

from .models import Device

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}


class DeviceTable(tables.Table):
    """Table representation of the Device model."""

    class Meta:
        """Table meta class configurations."""

        model = Device
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = 'There are no Devices available.'
        empty_text = format_html('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'device_name',
            'serial_number',
            'endpoint_profile',
            'onboarding_protocol',
            'device_onboarding_status',
            'onboarding_action',
            'details',
            'update',
            'delete'
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    endpoint_profile = tables.Column(
        empty_values=(None, '',),
        orderable=True,
        accessor='endpoint_profile.unique_endpoint',
        verbose_name='Endpoint Profile')
    onboarding_action = tables.Column(
        empty_values=(),
        orderable=False,
        verbose_name='Onboarding'
    )
    details = tables.Column(empty_values=(), orderable=False)
    update = tables.Column(empty_values=(), orderable=False)
    delete = tables.Column(empty_values=(), orderable=False)

    @staticmethod
    def render_onboarding_action(record: Device) -> str:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        if not record.endpoint_profile:
            return ''
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.NOT_ONBOARDED:
            return format_html(
                '<a href="onboarding/start/{}/" class="btn btn-primary tp-table-btn"">Start Onboarding</a>',
                record.pk)
        elif record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="onboarding/retry/{}/" class="btn btn-warning tp-table-btn"">Retry Onboarding</a>',
                record.pk)
        elif record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            return format_html(
                '<a href="onboarding/revoke/{}/" class="btn btn-warning tp-table-btn"">Revoke Onboarding</a>',
                record.pk)
        elif record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return format_html(
                '<a href="onboarding/cancel/{}/" class="btn btn-secondary tp-table-btn"">Cancel Onboarding</a>',
                record.pk)

    @staticmethod
    def render_details(record: Device) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">Details</a>', record.pk)

    @staticmethod
    def render_update(record: Device) -> SafeString:
        """Creates the html hyperlink for the update-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the update-view.
        """
        return format_html('<a href="update/{}/" class="btn btn-primary tp-table-btn">Update</a>', record.pk)

    @staticmethod
    def render_delete(record: Device) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">Delete</a>', record.pk)
