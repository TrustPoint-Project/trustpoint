"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html

from .exceptions import UnknownOnboardingProtocolError, UnknownOnboardingStatusError
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
            'device_serial_number',
            'endpoint_profile',
            'onboarding_protocol',
            'device_onboarding_status',
            'onboarding_action',
            'details',
            'update',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    endpoint_profile = tables.Column(
        empty_values=(None, ''),
        orderable=True,
        accessor='endpoint_profile.unique_endpoint',
        verbose_name='Endpoint Profile',
    )
    onboarding_action = tables.Column(empty_values=(), orderable=False, verbose_name='Onboarding Action')
    details = tables.Column(empty_values=(), orderable=False)
    update = tables.Column(empty_values=(), orderable=False)
    delete = tables.Column(empty_values=(), orderable=False)

    @staticmethod
    def render_device_onboarding_status(record: Device) -> str:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            str: The html hyperlink for the details-view.
        """
        if not record.endpoint_profile:
            return format_html('<span class="text-danger">Select Endpoint Profile</span>')
        return format_html(
            f'<span class="text-{Device.DeviceOnboardingStatus.get_color(record.device_onboarding_status)}">'
            f'{record.get_device_onboarding_status_display()}'
            '</span>'
        )

    @staticmethod
    def _render_manual_onboarding_action(record: Device) -> str:
        """Renders the device onboarding section for the manual onboarding cases.

        Args:
            record (Device):
                Record / instance of the device model.

        Returns:
            str:
                The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingStatusError:
                Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
        """
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.NOT_ONBOARDED:
            return format_html(
                '<a href="{}" class="btn btn-success tp-onboarding-btn">Start Onboarding</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': record.pk}),
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="{}" class="btn btn-warning tp-onboarding-btn">Retry Onboarding</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': record.pk}),
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.REVOKED:
            return format_html(
                '<a href="{}" class="btn btn btn-info tp-onboarding-btn">Revoked</a>',
                reverse('onboarding:revoke', kwargs={'device_id': record.pk}),
            )
        raise UnknownOnboardingStatusError

    @staticmethod
    def _render_zero_touch_onboarding_action(record: Device) -> str:
        """Renders the device onboarding section for the manual onboarding cases.

        Args:
            record (Device):
                Record / instance of the device model.

        Returns:
            str: The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingStatusError:
                Raised when an unknown onboarding status was found and thus cannot be rendered appropriately.
        """
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.NOT_ONBOARDED:
            return format_html(
                '<button class="btn btn-success tp-onboarding-btn" disabled>Zero-Touch Pending</a>', record.pk
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="onboarding/reset/{}/" class="btn btn-warning tp-onboarding-btn">Reset Context</a>',
                record.pk,
            )
        raise UnknownOnboardingStatusError

    def render_onboarding_action(self: DeviceTable, record: Device) -> str:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            str: The html hyperlink for the details-view.

        Raises:
            UnknownOnboardingProtocolError:
                Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately.
        """
        if not record.endpoint_profile:
            return ''

        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            return format_html(
                '<a href="{}" class="btn btn-danger tp-onboarding-btn">Revoke Certificate</a>',
                reverse('onboarding:revoke', kwargs={'device_id': record.pk}),
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return format_html(
                '<a href="{}" class="btn btn-danger tp-onboarding-btn">Cancel Onboarding</a>',
                reverse('onboarding:exit', kwargs={'device_id': record.pk}),
            )

        is_manual = record.onboarding_protocol == Device.OnboardingProtocol.MANUAL
        is_cli = record.onboarding_protocol == Device.OnboardingProtocol.CLI
        is_client = record.onboarding_protocol == Device.OnboardingProtocol.TP_CLIENT
        if is_cli or is_client or is_manual:
            return self._render_manual_onboarding_action(record)

        is_brski = record.onboarding_protocol == Device.OnboardingProtocol.BRSKI
        is_fido = record.onboarding_protocol == Device.OnboardingProtocol.FIDO
        if is_brski or is_fido:
            return self._render_zero_touch_onboarding_action(record)

        raise UnknownOnboardingProtocolError

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
