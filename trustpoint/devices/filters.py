"""Provides filtering functionality for the devices app.

This module defines filters for querying and filtering Device objects
based on various criteria. It leverages Django's django-filters package
to implement customizable filter sets with user-friendly widgets.
"""
from __future__ import annotations

from typing import ClassVar

import django_filters
from django import forms
from pki.models import DomainModel
from taggit.models import Tag

from devices import DeviceOnboardingStatus, OnboardingProtocol

from .models import Device


class DeviceFilter(django_filters.FilterSet):
    """Filter set for the Device model.

    This class provides filters for querying `Device` objects based on specific fields.
    It uses Django's `django_filters.FilterSet` to enable filtering through the UI
    with widgets for input.

    Attributes:
        device_name (django_filters.CharFilter):
            Filters devices by name using a case-insensitive `icontains` lookup.
            - Field Name: `device_name`
            - Widget: `forms.TextInput`

        tags (django_filters.ModelMultipleChoiceFilter):
            Filters devices by associated tags.
            - Queryset: All tags (`Tag.objects.all()`)
            - Widget: `forms.CheckboxSelectMultiple`
            - Label: Empty string (`''`)

        device_onboarding_status (django_filters.ChoiceFilter):
            Filters devices by their onboarding status.
            - Choices: Defined by `DeviceOnboardingStatus`
            - Widget: `forms.Select`

        onboarding_protocol (django_filters.ChoiceFilter):
            Filters devices by their onboarding protocol.
            - Choices: Defined by `OnboardingProtocol`
            - Widget: `forms.Select`

        domain (django_filters.ModelChoiceFilter):
            Filters devices by their associated domain.
            - Queryset: All domains (`DomainModel.objects.all()`)
            - Widget: `forms.Select`

    Example:
        Usage in a view to filter devices:
        ```python
        from .filters import DeviceFilter

        def device_list_view(request):
            filterset = DeviceFilter(request.GET, queryset=Device.objects.all())
            return render(request, 'device_list.html', {'filterset': filterset})
        ```
    """
    device_name = django_filters.CharFilter(
        field_name='device_name',
        lookup_expr='icontains',
        label='Device Name',
        widget=forms.TextInput(attrs={'class': 'textinput form-control'}),
    )

    tags = django_filters.ModelMultipleChoiceFilter(
        queryset=Tag.objects.all(), widget=forms.CheckboxSelectMultiple(), label=''
    )

    device_onboarding_status = django_filters.ChoiceFilter(
        choices=DeviceOnboardingStatus, widget=forms.Select(attrs={'class': 'form-select'})
    )

    onboarding_protocol = django_filters.ChoiceFilter(
        choices=OnboardingProtocol, widget=forms.Select(attrs={'class': 'form-select'})
    )

    domain = django_filters.ModelChoiceFilter(
        queryset=DomainModel.objects.all(), widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        """Meta options for the DeviceFilter.

        Defines the model and fields that are available for filtering.
        """
        model = Device
        fields: ClassVar[list[str]] = [
            'device_name',
            'device_onboarding_status',
            'onboarding_protocol',
            'domain',
            'tags'
        ]
