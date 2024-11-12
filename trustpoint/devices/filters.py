import django_filters
from django import forms
from taggit.models import Tag

from devices import DeviceOnboardingStatus

from .models import Device
from pki.models import DomainModel


class DeviceFilter(django_filters.FilterSet):
    device_name = django_filters.CharFilter(
        field_name='device_name', lookup_expr='icontains', label='Device Name',
        widget=forms.TextInput(attrs={'class': 'textinput form-control'})
    )

    tags = django_filters.ModelMultipleChoiceFilter(
        queryset=Tag.objects.all(),
        widget=forms.CheckboxSelectMultiple(),
        label=''
    )

    device_onboarding_status = django_filters.ChoiceFilter(
        choices=DeviceOnboardingStatus,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    onboarding_protocol = django_filters.ChoiceFilter(
        choices=Device.OnboardingProtocol,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    domain = django_filters.ModelChoiceFilter(
        queryset=DomainModel.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'})
    )


    class Meta:
        model = Device
        fields = ['device_name', 'device_onboarding_status', 'onboarding_protocol', 'domain', 'tags']
