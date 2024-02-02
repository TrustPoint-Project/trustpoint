from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='sysconf'),
    path('logging/', views.logging, name='sysconf-logging'),
    path('network/', views.network, name='sysconf-network'),
    path('ntp/', views.ntp, name='sysconf-ntp'),
    path('ssh/', views.ssh, name='sysconf-ssh')
]
