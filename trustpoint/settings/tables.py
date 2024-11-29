from __future__ import annotations

import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html

CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

class LogFileTable(tables.Table):

    class Meta:
        template_name = "django_tables2/bootstrap5.html"
        order_by = '-first_entry_date'

    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='filename', attrs=CHECKBOX_ATTRS)
    filename = tables.Column(verbose_name="Log-File")
    first_log_entry = tables.Column(verbose_name="First Log Entry", accessor='created_at')
    last_log_entry = tables.Column(verbose_name="Last Log Entry", accessor='updated_at')
    view = tables.Column(empty_values=(), orderable=False, verbose_name="View")
    download = tables.Column(empty_values=(), orderable=False, verbose_name="Download")

    @staticmethod
    def render_filename(record):
        log_detail_url = reverse('settings:logging-files-details', kwargs={'filename': record.get('filename')})
        return format_html('<a href="{}">{}</a>', log_detail_url, record.get('filename'))

    @staticmethod
    def render_view(record):
        log_download_url = reverse('settings:logging-files-details', kwargs={'filename': record.get('filename')})
        return format_html('<a href="{}" class="btn btn-primary tp-table-btn">View</a>', log_download_url)

    @staticmethod
    def render_download(record):
        log_download_url = reverse('settings:logging-files-download', kwargs={'filename': record.get('filename')})
        return format_html('<a href="{}" class="btn btn-primary tp-table-btn">Download</a>', log_download_url)
