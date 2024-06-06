"""Module that contains all tables corresponding to the PKI application."""


from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.html import format_html
from django.utils.functional import lazy
from django.utils.translation import gettext_lazy as _

from .models import EndpointProfile, IssuingCa, RootCa, Truststore

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

format_html_lazy = lazy(format_html, str)

class IssuingCaTable(tables.Table):
    """Table representation of the IssuingCa model."""

    class Meta:
        """Table meta class configurations."""

        model = IssuingCa
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Issuing CAs available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)
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
            'crl'
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))
    crl = tables.Column(empty_values=(), orderable=False, verbose_name=_('CRL'))

    @staticmethod
    def render_details(record: IssuingCa) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (IssuingCa): The current record of the IssuingCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_delete(record: IssuingCa) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (IssuingCa): The current record of the IssuingCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))

    @staticmethod
    def render_crl(record: IssuingCa) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (IssuingCa): The current record of the IssuingCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="/pki/download-crl/{}/" class="btn btn-primary" download>Download CRL</a>', record.pk)

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
        _msg = _('There are no Endpoint Profiles available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'unique_endpoint',
            'unique_name',
            'algorithm',
            'key_size',
            'curve',
            'details',
            'update',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    unique_name = tables.Column(
        empty_values=(
            None,
            '',
        ),
        orderable=True,
        accessor='issuing_ca.unique_name',
        verbose_name=_('Issuing CA'),
    )
    algorithm = tables.Column(
        empty_values=(
            None,
            '',
        ),
        orderable=True,
        accessor='issuing_ca.key_type',
        verbose_name=_('Issuing CA Algorithm'),
    )
    key_size = tables.Column(
        empty_values=(
            None,
            '',
        ),
        orderable=True,
        accessor='issuing_ca.key_size',
        verbose_name=_('Issuing CA Key Size'),
    )
    curve = tables.Column(
        empty_values=(
            None,
            '',
        ),
        orderable=True,
        accessor='issuing_ca.curve',
        verbose_name=_('Issuing CA Curve'),
    )
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    update = tables.Column(empty_values=(), orderable=False, verbose_name=_('Update'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_update(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the update-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the update-view.
        """
        return format_html('<a href="update/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Update'))

    @staticmethod
    def render_delete(record: EndpointProfile) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (EndpointProfile): The current record of the EndpointProfile model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))

# ---------------

class RootCaTable(tables.Table):
    """Table representation of the RootCa model."""

    class Meta:
        """Table meta class configurations."""

        model = RootCa
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Root CAs available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)
        fields = (
            'row_checkbox',
            'unique_name',
            'common_name',
            'not_valid_after',
            'ca_type',
            'details',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: RootCa) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (RootCa): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_delete(record: RootCa) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (RootCa): The current record of the RootCa model.

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

class TruststoreTable(tables.Table):
    """Table representation of the Truststore model."""

    class Meta:
        """Table meta class configurations."""

        model = Truststore
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
    def render_details(record: Truststore) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_delete(record: Truststore) -> SafeString:
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