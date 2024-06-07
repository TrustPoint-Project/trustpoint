"""URL configuration for the PKI application."""

from django.urls import path

from . import views

app_name = 'pki'

urlpatterns = [
    path('truststores/', views.TruststoreListView.as_view(), name='truststores'),
]
