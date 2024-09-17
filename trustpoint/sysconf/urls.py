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
    path('ntp/', views.ntp, name='ntp'),
    path('ssh/', views.ssh, name='ssh'),
    path('security/', views.security, name='security'),

]
