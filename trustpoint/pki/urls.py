"""URL configuration for the PKI application."""

from django.urls import path, re_path

from . import views

app_name = 'pki'

urlpatterns = [
    path('certificates/', views.CertificateTableView.as_view(), name='certificates'),
    re_path(
        r'^certificates/download/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.CertificateDownloadView.as_view(),
        name='certificates-download',
    ),
    re_path(
        r'^certificates/details/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.CertificateDownloadView.as_view(),
        name='certificates-details',
    ),
]
