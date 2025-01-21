"""This module defines Django Tables for the Trustpoint PKI application."""

from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.functional import lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import CertificateModel, DomainModel, IssuingCaModel
from .models.truststore import TruststoreModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

format_html_lazy = lazy(format_html, str)

class TruststoreTable(tables.Table):
    """Table representation of the Truststore model."""

    class Meta:
        """Table metaclass configurations."""

        model = TruststoreModel
        template_name = 'django_tables2/bootstrap5.html'
        empty_values = ()
        _msg = _('There are no Truststores available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = ('row_checkbox', 'unique_name', 'intended_usage', 'created_at', 'details', 'download')

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))

    @staticmethod
    def render_details(record: TruststoreModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (TruststoreModel): The current record of the Truststore model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_download(record: TruststoreModel) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the Truststore model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="download/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Download'))


class CertificateTable(tables.Table):
    """Table representation of the Certificate model."""

    class Meta:
        """Table metaclass configurations."""

        model = CertificateModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Certificates available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'common_name',
            'not_valid_after',
            'spki_algorithm',
            'spki_key_size',
            'spki_ec_curve',
            'certificate_status',
            'created_at',
            'is_self_signed',
            'details',
            'download',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    download = tables.Column(empty_values=(), orderable=False, verbose_name=_('Download'))

    @staticmethod
    def render_details(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="details/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_download(record: CertificateModel) -> SafeString:
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

    common_name = tables.Column(
        verbose_name=_('Common Name'),
        accessor='credential__certificate__common_name')

    not_valid_after = tables.Column(
        verbose_name=_('Not Valid After'),
        accessor='credential__certificate__not_valid_after'
    )

    signature_algorithm = tables.Column(
        verbose_name=_('Signature-Suite'),
        accessor='credential__certificate__signature_algorithm'
    )

    updated_at = tables.Column(
        verbose_name=_('Updated'),
        accessor='credential__certificate__created_at'
    )

    class Meta:
        """Table metaclass configurations."""

        model = IssuingCaModel
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
            'signature_algorithm',
            'updated_at',
            'created_at',
            'details',
            'config',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    config = tables.Column(empty_values=(), orderable=False, verbose_name=_('Config'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="detail/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_delete(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))

    @staticmethod
    def render_config(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the config-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the config-view.
        """
        return format_html('<a href="config/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Config'))


class DomainTable(tables.Table):
    """Table representation of the Domain model."""

    issuing_ca = tables.Column(
        verbose_name=_('Issuing CA Name'),
        accessor='issuing_ca__unique_name')

    class Meta:
        """Table metaclass configurations."""

        model = DomainModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Domain available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'unique_name',
            'issuing_ca',
            'details',
            'config',
            'delete',
        )

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    config = tables.Column(empty_values=(), orderable=False, verbose_name=_('Config'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the details-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        return format_html('<a href="detail/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Details'))

    @staticmethod
    def render_config(record: CertificateModel) -> SafeString:
        """Create the HTML hyperlink for the config-view.

        Args:
            record (CertificateModel): The current record of the Certificate model.

        Returns:
            SafeString: The HTML hyperlink for the config-view.
        """
        return format_html('<a href="config/{}/" class="btn btn-primary tp-table-btn">{}</a>',
                           record.pk, _('Config'))

    @staticmethod
    def render_delete(record: CertificateModel) -> SafeString:
        """Creates the html hyperlink for the delete-view.

        Args:
            record (Truststore): The current record of the RootCa model.

        Returns:
            SafeString: The html hyperlink for the delete-view.
        """
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn">{}</a>',
                           record.pk, _('Delete'))
