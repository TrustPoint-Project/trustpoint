"""Module that contains all tables corresponding to the PKI application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html

from .models import IssuingCa, EndpointProfile

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}


class IssuingCaTable(tables.Table):
    """Table representation of the IssuingCa model."""

    class Meta:
        """Table meta class configurations."""

        model = IssuingCa
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = 'There are no Issuing CAs available.'
        empty_text = format_html('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'unique_name',
            'common_name',
            'not_valid_after',
            'key_type',
            'key_size',
            'curve',
            'localization',
            'config_type',
            'details',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False)
    delete = tables.Column(empty_values=(), orderable=False)

    @staticmethod
    def render_details(record: IssuingCa) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (IssuingCa): The current record of the IssuingCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">Details</a>', record.pk)

    @staticmethod
    def render_delete(record: IssuingCa) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (IssuingCa): The current record of the IssuingCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">Delete</a>', record.pk)

    # TODO(Alex): consider explicitly not supporting multiple CNs
    # TODO(Alex): there were cases in the past in which this was misused due to software not handling this correctly
    @staticmethod
    def render_common_name(value: str) -> SafeString:
        """Creates the string representation of the corresponding common name by adding line breaks if required.

        Args:
            value (str): The string value of the common name field.

        Returns:
            SafeString: String representation of the corresponding common name with added line breaks.
        """
        common_names = value.split('<br>')
        msg = ''
        for i in range(1, len(common_names) + 1):
            if i != len(common_names):
                msg += '{}<br>'
            else:
                msg += '{}'
        return format_html(msg, *common_names)


class EndpointProfileTable(tables.Table):
    """Table representation of the EndpointProfile model."""

    class Meta:
        """Table meta class configurations."""

        model = EndpointProfile
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = 'There are no Endpoint Profiles available.'
        empty_text = format_html('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'unique_endpoint',
            'unique_name',
            'algorithm',
            'key_size',
            'curve',
            'details',
            'update',
            'delete'
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    unique_name = tables.Column(
        empty_values=(None, '',),
        orderable=True,
        accessor='issuing_ca.unique_name',
        verbose_name='Issuing CA')
    algorithm = tables.Column(
        empty_values=(None, '',),
        orderable=True,
        accessor='issuing_ca.key_type',
        verbose_name='Issuing CA Algorithm')
    key_size = tables.Column(
        empty_values=(None, '',),
        orderable=True,
        accessor='issuing_ca.key_size',
        verbose_name='Issuing CA Key Size')
    curve = tables.Column(
        empty_values=(None, '',),
        orderable=True,
        accessor='issuing_ca.curve',
        verbose_name='Issuing CA Curve')
    details = tables.Column(empty_values=(), orderable=False)
    update = tables.Column(empty_values=(), orderable=False)
    delete = tables.Column(empty_values=(), orderable=False)

    @staticmethod
    def render_details(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">Details</a>', record.pk)

    @staticmethod
    def render_update(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the update-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the update-view.
        """
        return format_html('<a href="update/{}/" class="btn btn-primary tp-table-btn">Update</a>', record.pk)

    @staticmethod
    def render_delete(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">Delete</a>', record.pk)



