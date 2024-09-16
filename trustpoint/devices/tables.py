"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .exceptions import UnknownOnboardingProtocolError, UnknownOnboardingStatusError
from .models import Device
from taggit.managers import TaggableManager

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
            'tags',
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
    tags = tables.Column(empty_values=(), orderable=False, verbose_name=_('Tags'), attrs={
        'td': {'class': 'tags-column'}
    })

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

    def render_onboarding_action(self: DeviceTable, record: Device) -> str:
        """Returns devices html hyperlink button for onboarding action for detail-view."""
        return record.render_onboarding_action()

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

    @staticmethod
    def render_tags(value: TaggableManager):
        """Renders the tags as a comma-separated list."""
        if value:
            return ', '.join([tag.name for tag in value.all()])
        return '-'
