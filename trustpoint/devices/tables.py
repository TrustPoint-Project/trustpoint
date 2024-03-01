"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.urls import reverse

from .models import Device

if TYPE_CHECKING:
    from typing import Any

    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}


class DisplayError(ValueError):
    """Raised when some entry in the table cannot be rendered appropriately."""

    def __init__(self: DisplayError, *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unique name is already taken. Try another one.'
        super().__init__(exc_msg, *args)


class UnknownOnboardingStatusError(DisplayError):
    """Raised when an unknown onboarding status was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingStatusError, *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unknown onboarding status. Failed to render entry in table.'
        super().__init__(exc_msg, *args)


class UnknownOnboardingProtocolError(DisplayError):
    """Raised when an unknown onboarding protocol was found and thus cannot be rendered appropriately."""

    def __init__(self: UnknownOnboardingProtocolError, *args: Any) -> None:
        """Add the error message by passing it to constructor of the parent class."""
        exc_msg = 'Unknown onboarding protocol. Failed to render entry in table.'
        super().__init__(exc_msg, *args)


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
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    endpoint_profile = tables.Column(
        empty_values=(None, ''),
        orderable=True,
        accessor='endpoint_profile.unique_endpoint',
        verbose_name='Endpoint Profile',
    )
    onboarding_action = tables.Column(empty_values=(), orderable=False, verbose_name='Onboarding')
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
                reverse("onboarding:manual-client", kwargs={'device_id': record.pk})
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="{}" class="btn btn-warning tp-onboarding-btn">Retry Onboarding</a>',
                reverse("onboarding:manual-client", kwargs={'device_id': record.pk})
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
                '<button class="btn btn-secondary tp-onboarding-btn" disabled>Zero-Touch Onboarding</a>', record.pk
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
                '<a href="onboarding/revoke/{}/" class="btn btn-danger tp-onboarding-btn">Revoke Onboarding</a>',
                record.pk,
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return format_html(
                '<a href="{}" class="btn btn-danger tp-onboarding-btn">Cancel Onboarding</a>',
                reverse("onboarding:exit", kwargs={'device_id': record.pk})
            )

        is_manual = record.onboarding_protocol == Device.OnboardingProtocol.MANUAL
        is_client = record.onboarding_protocol == Device.OnboardingProtocol.CLIENT
        if is_manual or is_client:
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
