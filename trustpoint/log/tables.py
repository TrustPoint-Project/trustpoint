import django_tables2 as tables
from django.urls import reverse
from django.utils.html import format_html

CHECKBOX_ATTRS: dict[str, dict[str, str]] = {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}

class LogFileTable(tables.Table):
    row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='filename', attrs=CHECKBOX_ATTRS)
    filename = tables.Column(verbose_name="Log Filename")
    date = tables.Column(verbose_name="Date Modified", accessor='date')
    actions = tables.Column(empty_values=(), orderable=False, verbose_name="Actions")

    class Meta:
        template_name = "django_tables2/bootstrap5.html"
        order_by = '-date'

    @staticmethod
    def render_filename(record):
        log_detail_url = reverse('log:log-detail', kwargs={'filename': record.get('filename')})
        return format_html('<a href="{}">{}</a>', log_detail_url, record.get('filename'))

    @staticmethod
    def render_actions(record):
        log_download_url = reverse('log:log-download', kwargs={'filename': record.get('filename')})
        return format_html('<a href="{}" class="btn btn-primary">Download</a>', log_download_url)
