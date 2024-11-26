"""Defines filter sets for querying and refining notification data."""
from datetime import timedelta

import django_filters
from django.db.models import QuerySet
from django.utils import timezone

from home.models import NotificationModel


class NotificationFilter(django_filters.FilterSet):
    """Filters Notification objects based on type, date range, and sources."""
    notification_type = django_filters.CharFilter(method='filter_by_multiple_types', label='Notification Type')
    notification_source = django_filters.CharFilter(method='filter_by_multiple_sources', label='Notification Source')
    date_range = django_filters.CharFilter(method='filter_by_date_range', label='Date Range')

    class Meta:
        """Meta configuration for the NotificationFilter, specifying the target model."""
        model = NotificationModel
        fields = ['notification_type', 'notification_source']

    def filter_by_multiple_types(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Filters the queryset based on the provided value types."""
        # Split the comma-separated values into a list for types
        if value:
            types = value.split(',')
            return queryset.filter(notification_type__in=types)
        return queryset

    def filter_by_multiple_sources(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Filters the queryset based on the provided value sources."""
        # Split the comma-separated values into a list for sources
        if value:
            sources = value.split(',')
            return queryset.filter(notification_source__in=sources)
        return queryset

    def filter_by_date_range(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        """Filters the queryset based on the provided value date range."""
        now = timezone.now()
        if value == 'today':
            return queryset.filter(created_at__date=now.date())
        if value == 'last7days':
            return queryset.filter(created_at__gte=now - timedelta(days=7))
        if value == 'last30days':
            return queryset.filter(created_at__gte=now - timedelta(days=30))
        if value == 'all':
            return queryset  # No filtering, return all
        return queryset
