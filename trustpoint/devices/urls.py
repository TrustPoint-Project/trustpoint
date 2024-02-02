from django.urls import path
from . import views


urlpatterns = [
    path('', views.devices, name='devices'),
    path('devices/', views.devices_devices, name='devices-devices'),
]
