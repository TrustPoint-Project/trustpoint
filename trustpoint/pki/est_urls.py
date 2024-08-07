"""URL configuration for the PKI application."""

from django.urls import path, re_path

from . import views

app_name = 'est'

urlpatterns = [
    path('issuing-ca/simpleenroll/', views.EstEndpoint.as_view(), name='simple_enroll')
]
