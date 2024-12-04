from datetime import datetime, timedelta
from django.utils import timezone
import django_filters
from home.models import NotificationModel

class NotificationFilter(django_filters.FilterSet):
    notification_type = django_filters.CharFilter(
        method='filter_by_multiple_types',
        label="Notification Type"
    )
    notification_source = django_filters.CharFilter(
        method='filter_by_multiple_sources',
        label="Notification Source"
    )
    date_range = django_filters.CharFilter(
        method='filter_by_date_range',
        label="Date Range"
    )

    class Meta:
        model = NotificationModel
        fields = ['notification_type', 'notification_source']

    def filter_by_multiple_types(self, queryset, name, value):
        # Split the comma-separated values into a list for types
        if value:
            types = value.split(',')
            return queryset.filter(notification_type__in=types)
        return queryset

    def filter_by_multiple_sources(self, queryset, name, value):
        # Split the comma-separated values into a list for sources
        if value:
            sources = value.split(',')
            return queryset.filter(notification_source__in=sources)
        return queryset

    def filter_by_date_range(self, queryset, name, value):
        now = timezone.now()
        if value == 'today':
            return queryset.filter(created_at__date=now.date())
        elif value == 'last7days':
            return queryset.filter(created_at__gte=now - timedelta(days=7))
        elif value == 'last30days':
            return queryset.filter(created_at__gte=now - timedelta(days=30))
        elif value == 'all':
            return queryset  # No filtering, return all
        return queryset
