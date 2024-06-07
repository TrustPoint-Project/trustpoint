from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.utils.functional import lazy
from django.utils.translation import gettext_lazy as _

from .models import TrustStore

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

format_html_lazy = lazy(format_html, str)


class TrustStoreTable(tables.Table):
    """Table representation of the Truststore model."""

    class Meta:
        """Table meta class configurations."""

        model = TrustStore
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Truststores available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)
        fields = (
            #'row_checkbox',
            'common_name',
            'subject',
            #'issuer',
            'not_valid_before',
            'not_valid_after',
            'key_type',
            'key_size',
            'curve',
            #'pem'
            'details',
            'delete',
        )

    #row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: TrustStore) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_delete(record: TrustStore) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))

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
