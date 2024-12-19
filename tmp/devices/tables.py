"""Module that contains all tables corresponding to the devices application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from devices.models import DeviceModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

class DeviceTable(tables.Table):
    """Table representation of the Certificate model."""

    class Meta:
        """Meta table configurations."""

        model = DeviceModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Devices available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'unique_name',
            'onboarding_status',
            'serial_number',
            'primary_domain',
            'modified_at',
            'created_at',
            # 'onboarding_action',
            'details',
            'edit',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    # onboarding_action = tables.Column(empty_values=(), orderable=False, verbose_name=_('Onboarding Action'))
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    edit = tables.Column(empty_values=(), orderable=False, verbose_name=_('Edit'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))


    @staticmethod
    def render_details(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_edit(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the edit-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the edit-view.
        """
        return format_html('<a href="edit/{}/" class="btn btn-primary tp-table-btn">{}</a>', record.pk, _('Edit'))

    @staticmethod
    def render_delete(record: DeviceModel) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))
