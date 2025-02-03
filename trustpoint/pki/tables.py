"""This module defines Django Tables for the Trustpoint PKI application."""

from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.urls import reverse_lazy
from django.utils.functional import lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from .models import CertificateModel, DomainModel, IssuingCaModel, DevIdRegistration
from .models.truststore import TruststoreModel

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}



class DevIdRegistrationTable(tables.Table):
    """Lists all DevID Registration Patterns with a delete option."""

    class Meta:
        """Meta table configurations."""
        model = DevIdRegistration
        template_name = 'django_tables2/bootstrap5.html'
        order_by = 'unique_name'
        empty_values = ()
        _msg = _('There are no DevID Registration Patterns available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)

        fields = ('unique_name', 'truststore', 'serial_number_pattern', 'delete')

    unique_name = tables.Column(orderable=True, verbose_name=_('Unique Name'))
    truststore = tables.Column(orderable=True, verbose_name=_('Truststore'))
    serial_number_pattern = tables.Column(orderable=True, verbose_name=_('Serial Number Pattern'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))


    @staticmethod
    def render_delete(record: DevIdRegistration) -> str:
        """Renders a delete button for each row."""
        return format_html(
            '<a href="{}" class="btn btn-danger tp-table-btn w-100">{}</a>',
            reverse_lazy('pki:devid_registration_delete', kwargs={'pk': record.id}),
            _('Delete'),
        )
