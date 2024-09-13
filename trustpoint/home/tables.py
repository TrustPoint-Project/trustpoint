"""Django tables2 for the home application."""
from __future__ import annotations

from typing import TYPE_CHECKING

import django_tables2 as tables
from django.utils.functional import lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from django.utils.safestring import SafeString


# CHECKBOX_ATTRS: dict[str, dict[str, str]] =
# {'th': {'id': 'checkbox-column'}, 'td': {'class': 'row_checkbox'}}    # noqa: ERA001

from home.models import NotificationModel, NotificationStatus

format_html_lazy = lazy(format_html, str)
class NotificationTable(tables.Table):
    """Table representation of the Notification model."""

    class Meta:
        """Table meta class configurations."""

        model = NotificationModel
        template_name = 'django_tables2/bootstrap5.html'
        order_by = '-created_at'
        empty_values = ()
        _msg = _('There are no Notifications available.')
        empty_text = format_html('<div class="text-center">{}</div>', _msg)
        fields = (
            # 'row_checkbox',   # noqa: ERA001
            'notification_type',
            'notification_source',
            'message',
            'created_at',
            'details',
            #'solve',
            'delete',
        )

    notification_type = tables.Column(
        verbose_name=_('Type')
    )

    notification_source = tables.Column(
        verbose_name=_('Source')
    )

    message = tables.Column(
        verbose_name=_('Description'),
        accessor='message__short_description'
    )


    # row_checkbox = tables.CheckBoxColumn(empty_values=(), accessor='pk', attrs=CHECKBOX_ATTRS)    # noqa: ERA001
    details = tables.Column(empty_values=(), orderable=False, verbose_name=_('Details'))
    #solve = tables.Column(empty_values=(), orderable=False, verbose_name=_('Solve'))
    delete = tables.Column(empty_values=(), orderable=False, verbose_name=_('Delete'))

    @staticmethod
    def render_details(record: NotificationModel) -> SafeString:
        """Creates the html hyperlink for the details-view."""
        return format_html('<a href="../notification/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
                           record.pk, _('Details'))

    # @staticmethod
    # def render_solve(record: NotificationModel) -> SafeString:
    #     """Creates the HTML hyperlink for the solve-view."""
    #     return format_html('<a href="solve/{}/" class="btn btn-primary tp-table-btn"">{}</a>',
    #                        record.pk, _('Solve'))

    @staticmethod
    def render_delete(record: NotificationModel) -> SafeString:
        """Creates the HTML hyperlink for the delete-view."""
        return format_html('<a href="delete/{}/" class="btn btn-secondary tp-table-btn"">{}</a>',
                           record.pk, _('Delete'))

    @staticmethod
    def render_created_at(record: NotificationModel) -> SafeString:
        """Render the created_at field with a badge if the status is 'New'."""
        created_at_display = record.created_at.strftime("%Y-%m-%d %H:%M:%S")

        if record.statuses.filter(status=NotificationStatus.StatusChoices.NEW).exists():
            return format_html(
                '{} <span class="badge bg-secondary">New</span>',
                created_at_display
            )

        return format_html('{}', created_at_display)

    @staticmethod
    def render_notification_type(record: NotificationModel) -> SafeString:
        """Render the notification type with a badge according to the type."""
        type_display = record.get_notification_type_display()

        if record.notification_type == NotificationModel.NotificationTypes.CRITICAL:
            badge_class = 'bg-danger'
        elif record.notification_type == NotificationModel.NotificationTypes.WARNING:
            badge_class = 'bg-warning'
        elif record.notification_type == NotificationModel.NotificationTypes.INFO:
            badge_class = 'bg-info'
        else:  # Setup or other types default to secondary
            badge_class = 'bg-secondary'

        return format_html('<span class="badge {}">{}</span>', badge_class, type_display)
