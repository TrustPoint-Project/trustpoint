"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

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
        _msg = _('There are no Devices available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'device_name',
            'device_serial_number',
            'domain',
            'onboarding_protocol',
            'device_onboarding_status',
            'onboarding_action',
            'details',
            'edit',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    device_name = tables.Column(empty_values=(), orderable=True, verbose_name=_('Device Name'))
    device_serial_number = tables.Column(empty_values=(), orderable=True, verbose_name=_('Serial Number'))
    onboarding_protocol = tables.Column(empty_values=(), orderable=True, verbose_name=_('Onboarding Protocol'))
    device_onboarding_status = tables.Column(empty_values=(), orderable=True, verbose_name=_('Onboarding Status'))
    domain = tables.Column(
        empty_values=(None, ''),
        orderable=True,
        accessor='domain.unique_name',
        verbose_name=_('Domain'),
    )
    onboarding_action = tables.Column(empty_values=(), orderable=False, verbose_name=_('Onboarding Action'))
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    edit = tables.Column(empty_values=(), orderable=False, verbose_name=_('Edit'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_device_onboarding_status(record: Device) -> str:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            str: The html hyperlink for the details-view.
        """
        if not record.domain:
            return format_html('<span class="text-danger">' + _('Select Domain') + '</span>')
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
                '<a href="{}" class="btn btn-success tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': record.pk}),
                _('Start Onboarding')
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="{}" class="btn btn-warning tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': record.pk}),
                _('Retry Onboarding')
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.REVOKED:
            return format_html(
                '<a href="{}" class="btn btn btn-info tp-onboarding-btn">{}</a>',
                reverse('onboarding:manual-client', kwargs={'device_id': record.pk}),
                _('Onboard again')
            )
        exc_msg = f'Unknown onboarding status {record.device_onboarding_status}. Failed to render entry in table.'
        raise UnknownOnboardingStatusError(record.device_onboarding_status)

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
                '<button class="btn btn-success tp-onboarding-btn" disabled>{}</a>',
                _('Zero-Touch Pending')
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_FAILED:
            return format_html(
                '<a href="onboarding/reset/{}/" class="btn btn-warning tp-onboarding-btn">{}</a>',
                record.pk, _('Reset Context')
            )
        raise UnknownOnboardingStatusError(record.device_onboarding_status)

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
        if not record.domain:
            return ''

        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDED:
            return format_html(
                '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
                reverse('onboarding:revoke', kwargs={'device_id': record.pk}),
                _('Revoke Certificate')
            )
        if record.device_onboarding_status == Device.DeviceOnboardingStatus.ONBOARDING_RUNNING:
            return format_html(
                '<a href="{}" class="btn btn-danger tp-onboarding-btn">{}</a>',
                reverse('onboarding:exit', kwargs={'device_id': record.pk}),
                _('Cancel Onboarding')
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

        #raise UnknownOnboardingProtocolError(record.onboarding_protocol)
        return format_html('<span class="text-danger">' + _('Unknown onboarding protocol!') + '</span>')

    @staticmethod
    def render_details(record: Device) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_edit(record: Device) -> SafeString:
        """Creates the html hyperlink for the edit-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the edit-view.
        """
        return format_html('<a href="edit/{}/" class="btn btn-primary tp-table-btn">{}</a>', record.pk, _('Edit'))

    @staticmethod
    def render_delete(record: Device) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))
