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
    path('ssh/', views.ssh, name='ssh'),
    path('security/', views.security, name='security'),
    path("ntp/", views.ManageNTPConfigView.as_view(), name="ntp"),
    path("toggle_ntp/<str:enable>/", views.ToggleNTPView.as_view(), name="toggle_ntp"),
    path("ntp-status/", views.NTPStatusView.as_view(), name="ntp_status"),

    #path('test-ntp-connection/', views.test_ntp_connection, name='test_ntp_connection'),
]
