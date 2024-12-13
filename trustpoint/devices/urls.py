"""URL configuration for the devices' application."""

from django.urls import path, re_path  # type: ignore[import-untyped]

from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='devices-add'),
    path('onboarding/manual/<int:pk>/', views.ManualOnboardingView.as_view(), name='manual'),
    path(
        'onboarding/manual/<int:pk>/<str:format>/',
        views.ManualOnboardingDownloadView.as_view(),
        name='manual_download'),
]