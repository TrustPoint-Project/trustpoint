import django_filters
from django import forms
from taggit.models import Tag

from .models import Device


class DeviceFilter(django_filters.FilterSet):
    device_name = django_filters.CharFilter(
        field_name='device_name', lookup_expr='icontains', label='Device Name'
    )

    tags = django_filters.ModelMultipleChoiceFilter(
        queryset=Tag.objects.all(),
        widget=forms.CheckboxSelectMultiple(),
        label=''
    )

    class Meta:
        model = Device
        fields = ['device_name', 'device_onboarding_status', 'onboarding_protocol', 'domain', 'tags']
