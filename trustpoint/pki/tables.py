from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.utils.functional import lazy
from django.utils.translation import gettext_lazy as _


from .models import Certificate, IssuingCa


if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

format_html_lazy = lazy(format_html, str)


class CertificateTable(tables.Table):
    """Table representation of the Certificate model."""

    # common_name = tables.Column(verbose_name=_('Common Name'), accessor='certificate__subject__')

    class Meta:
        """Table meta class configurations."""

        model = Certificate
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Certificates available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'common_name',
            'certificate_hierarchy_type',
            'not_valid_after',
            'spki_algorithm',
            'spki_key_size',
            'spki_ec_curve',
            'details',
            'download',
            # 'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))
    # delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: Certificate) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="detail/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    # @staticmethod
    # def render_delete(record: Certificate) -> SafeString:
    #     """Creates the html hyperlink for the delete-view.
    #
    #     Args:
    #         record (Truststore): The current record of the RootCa model.
    #
    #     Returns:
    #         SafeString: The html hyperlink for the delete-view.
    #     """
    #     return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
    #                        record.pk, _('Delete'))

    @staticmethod
    def render_download(record: Certificate) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="download/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Download'))


class IssuingCaTable(tables.Table):
    """Table representation of the Issuing CA model."""

    # common_name = tables.Column(verbose_name=_('Common Name'), accessor='certificate__subject__')

    class Meta:
        """Table meta class configurations."""

        model = IssuingCa
        template_name = 'django_tables2/bootstrap5.html'
        # order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Certificates available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'unique_name',
            'cert',
            'details',
            'download'
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))

    @staticmethod
    def render_details(record: Certificate) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="detail/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_download(record: Certificate) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="download/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Download'))

    @staticmethod
    def render_delete(record: Certificate) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))
