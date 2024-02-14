from django.urls import path
from . import views


app_name = 'sysconf'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('logging/', views.logging, name='logging'),
    path('network/', views.network, name='network'),
    path('ntp/', views.ntp, name='ntp'),
    path('ssh/', views.ssh, name='ssh')
]