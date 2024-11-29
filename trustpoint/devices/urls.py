"""URL configuration for the application devices."""

from django.urls import path

from .views import DeviceListView, CreateDeviceView

app_name = 'devices'
urlpatterns = [
    path('', DeviceListView.as_view(), name='devices'),
    path('add/', CreateDeviceView.as_view(), name='devices-add'),
]
