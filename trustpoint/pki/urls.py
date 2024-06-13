"""URL configuration for the PKI application."""

from django.urls import path

from . import views

app_name = 'pki'

urlpatterns = [
    path('certificates/', views.CertificateListView.as_view(), name='certificates'),
    path('credentials/', views.CredentialListView.as_view(), name='credentials'),
    path('truststores/', views.TruststoreListView.as_view(), name='truststores'),
]
