import django_tables2 as tables
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _


from .models import IssuingCa


class IssuingCaTable(tables.Table):

    class Meta:
        model = IssuingCa
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = tuple()
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
            'export',
            'delete')

    attrs = {
        'th': {
            'id': 'checkbox-column'
        },
        'td': {
            'class': 'row_checkbox'
        }
    }

    row_checkbox = tables.CheckBoxColumn(empty_values=tuple(), accessor='pk', attrs=attrs)
    details = tables.Column(empty_values=tuple(), orderable=False)
    export = tables.Column(empty_values=tuple(), orderable=False)
    delete = tables.Column(empty_values=tuple(), orderable=False)

    def render_details(self, record):
        return format_html(
            '<a href="details/{}/" class="btn btn-primary tp-table-btn"">Details</a>',
            record.pk)

    def render_export(self, record):
        return format_html(
            '<a href="export/{}/" class="btn btn-primary tp-table-btn"">Export</a>',
            record.pk)

    def render_delete(self, record):
        return format_html(
            '<a href="delete/{}/" class="btn btn-secondary tp-table-btn">Delete</a>',
            record.pk)

    # TODO: consider explicitly not supporting multiple CNs
    # TODO: there were cases in the past in which this was misused due to software not handling this correctly
    def render_common_name(self, value) -> str:
        common_names = value.split('<br>')
        msg = ''
        for i in range(1, len(common_names) + 1):
            if i != len(common_names):
                msg += '{}<br>'
            else:
                msg += '{}'
        return format_html(msg, *common_names)

    # TODO: consider explicitly not supporting multiple CNs
    # TODO: there were cases in the past in which this was misused due to software not handling this correctly
    def render_root_common_name(self, value) -> str:
        common_names = value.split('<br>')
        msg = ''
        for i in range(1, len(common_names) + 1):
            if i != len(common_names):
                msg += '{}<br>'
            else:
                msg += '{}'
        return format_html(msg, *common_names)

