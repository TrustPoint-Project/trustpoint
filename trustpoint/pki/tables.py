"""Module that contains all tables corresponding to the PKI application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html

from .models import IssuingCa

if TYPE_CHECKING:
    from typing import ClassVar

    from django.utils.safestring import SafeString


class IssuingCaTable(tables.Table):
    """Table representation of the IssuingCa model."""

    _attrs: ClassVar[dict[str, dict[str, str]]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

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

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=_attrs)
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
