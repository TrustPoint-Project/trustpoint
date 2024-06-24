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
    path('certificates/detail/<pk>/', views.CertificateDetailView.as_view(), name='certificate-detail'),
    path('issuing-cas/', views.IssuingCaTableView.as_view(), name='issuing_cas'),
    path(
        'issuing-cas/add/method-select/',
        views.IssuingCaAddMethodSelectView.as_view(),
        name='issuing_cas-add-method_select'),
    path(
        'issuing-cas/add/file-import/',
        views.IssuingCaAddFileImportView.as_view(),
        name='issuing_cas-add-file_import'
    )
]

