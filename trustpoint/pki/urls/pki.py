"""URL configuration for the PKI application."""

from django.urls import path, re_path

from pki.views import certificates, issuing_cas, domains

app_name = 'pki'

urlpatterns = [
    path(
        'certificates/',
        certificates.CertificateTableView.as_view(),
        name='certificates',
    ),
    path(
        'certificates/issued-certificates/<int:pk>/',
        certificates.IssuedCertificatesTableView.as_view(),
        name='issued_certificates'),
    re_path(
        r'^certificates/download/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-download'),
    re_path(
        r'^certificates/download/(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-download'
    ),
    re_path(
        r'^certificates/download/multiple/'
        r'(?P<file_format>[a-zA-Z0-9_]+)/'
        r'(?P<archive_format>[a-zA-Z0-9_]+)/'
        r'(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-file-download'
    ),
    re_path(
        r'^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-file-download',
    ),
    path('certificates/details/<int:pk>/', certificates.CertificateDetailView.as_view(), name='certificate-details'),
    path('issuing-cas/', issuing_cas.IssuingCaTableView.as_view(), name='issuing_cas'),
    path(
        'issuing-cas/add/method-select/',
        issuing_cas.IssuingCaAddMethodSelectView.as_view(),
        name='issuing_cas-add-method_select'),
    path(
        'issuing-cas/add/file-import/pkcs12',
        issuing_cas.IssuingCaAddFileImportPkcs12View.as_view(),
        name='issuing_cas-add-file_import-pkcs12'
    ),
    path(
        'issuing-cas/add/file-import/separate-files',
        issuing_cas.IssuingCaAddFileImportSeparateFilesView.as_view(),
        name='issuing_cas-add-file_import-separate_files'
    ),
    path('issuing-cas/detail/<int:pk>/', issuing_cas.IssuingCaDetailView.as_view(), name='issuing_cas-detail'),
    path('issuing-cas/config/<int:pk>/', issuing_cas.IssuingCaConfigView.as_view(), name='issuing_cas-config'),
    re_path(
        r'^issuing-cas/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        issuing_cas.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),
    path('domains/', domains.DomainTableView.as_view(), name='domains'),
    path(
        'domains/add/',
        domains.DomainCreateView.as_view(),
        name='domains-add'
    ),
    path(
        'domains/config/<int:pk>/',
        domains.DomainConfigView.as_view(),
        name='domains-config'
    ),
    path(
        'domains/detail/<int:pk>/',
        domains.DomainDetailView.as_view(),
        name='domains-detail'),
    re_path(
        r'^domains/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        domains.DomainCaBulkDeleteConfirmView.as_view(),
        name='domains-delete_confirm',
    ),
]
