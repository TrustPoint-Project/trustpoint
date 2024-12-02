from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.functional import lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import CertificateModel, DomainModel, IssuingCaModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

format_html_lazy = lazy(format_html, str)


class CertificateTable(tables.Table):
    """Table representation of the Certificate model."""

    class Meta:
        """Table meta class configurations."""

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
            'added_at',
            'is_self_signed',
            'is_root_ca',
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
        return format_html('<a href="detail/{}/" class="btn btn-primary tp-table-btn">{}</a>',
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
        verbose_name=_('Issuing CA - Common Name'),
        accessor='issuing_ca_certificate__common_name')

    not_valid_after = tables.Column(
        verbose_name=_('Issuing CA - Not Valid After'),
        accessor='issuing_ca_certificate__not_valid_after'
    )

    signature_algorithm = tables.Column(
        verbose_name=_('Issuing CA - Signature Algorithm'),
        accessor='issuing_ca_certificate__signature_algorithm'
    )

    class Meta:
        """Table meta class configurations."""

        model = IssuingCaModel
        template_name = 'django_tables2/bootstrap5.html'
        # order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Issuing CAs available.')
        empty_text = format_html_lazy('<div class="text-center">{}</div>', _msg)

        fields = (
            'row_checkbox',
            'unique_name',
            'common_name',
            'not_valid_after',
            'signature_algorithm',
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
        verbose_name=_('Issuing CA - Common Name'),
        accessor='issuing_ca__issuing_ca_certificate__common_name')

    class Meta:
        """Table meta class configurations."""

        model = DomainModel
        template_name = 'django_tables2/bootstrap5.html'
        # order_by = '-created_at'
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


class ProtocolConfigTable(tables.Table):
    """Table representation of the different protocols."""
    protocol = tables.Column(verbose_name='Protocol')
    status = tables.Column(verbose_name='Status')
    operation = tables.Column(verbose_name='Operation')
    action = tables.Column(verbose_name='Action')
    url_path = tables.Column(verbose_name='URL Path')
    details = tables.Column(verbose_name='Details', accessor='get_details_link', orderable=False)
    configure = tables.Column(verbose_name='Configure', accessor='get_configure_link', orderable=False)

    def render_status(self, value):
        """Color status based on its value"""
        if value == "Enabled":
            return format_html('<span class="text-success">{}</span>', value)
        elif value == "Disabled":
            return format_html('<span class="text-muted">{}</span>', value)
        elif value == "Limited":
            return format_html('<span class="text-warning">{}</span>', value)

    def render_action(self, value):
        """Render action buttons"""
        return format_html('<button class="btn btn-secondary">{}</button>', value)

    class Meta:
        template_name = 'django_tables2/bootstrap4.html'
