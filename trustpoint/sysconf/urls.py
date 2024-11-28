"""Routing configuration"""
from django.urls import path

from . import views
from .views import LoggingConfigView

app_name = 'sysconf'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('language/', views.language, name='language'),
    path('logging/', LoggingConfigView.as_view(), name='logging'),
    path('network/', views.network, name='network'),
    path('ntp/', views.ntp_configuration_view, name='ntp'),
    path('test-ntp-connection/', views.test_ntp_connection, name='test_ntp_connection'),
    path('ssh/', views.ssh, name='ssh'),
    path('security/', views.security, name='security'),

]
