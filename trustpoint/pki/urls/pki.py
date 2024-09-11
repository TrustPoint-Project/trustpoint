"""URL configuration for the PKI application."""

from django.urls import path, re_path

from ..views import certificates, crls, domains, issuing_cas, trust_stores

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
        r'^certificates/download/multiple/(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-download'
    ),
    re_path(
        r'^certificates/download/multiple/'
        r'(?P<file_format>[a-zA-Z0-9_]+)/'
        r'(?P<file_content>[a-zA-Z0-9_]+)/'
        r'(?P<archive_format>[a-zA-Z0-9_]+)/'
        r'(?P<pks>([0-9]+/)+[0-9]+)/?$',
        certificates.CertificateMultipleDownloadView.as_view(),
        name='certificates-file-download'
    ),
    re_path(
        r'^certificates/download/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(short=True),
        name='certificate-download'),
    re_path(
        r'^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<file_content>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$',
        certificates.CertificateDownloadView.as_view(short=False),
        name='certificate-file-download',
    ),
    path('certificates/detail/<int:pk>/', certificates.CertificateDetailView.as_view(), name='certificate-detail'),
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
    path('ca-crl/<int:ca_id>/',
         crls.CRLDownloadView.download_ca_crl,
         name='download-ca-crl'),
    path('generate-ca-crl/<int:ca_id>/',
         crls.CRLDownloadView.generate_ca_crl,
         name='generate-ca-crl'),
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
        r'^domains/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        domains.DomainBulkDeleteConfirmView.as_view(),
        name='domains-delete_confirm',
    ),
    path('truststores/', trust_stores.TrustStoresTableView.as_view(), name='truststores'),
    path(
        'truststores/add/',
        trust_stores.TrustStoreAddView.as_view(),
        name='truststores-add'
    ),
    re_path(
        r'^truststores/download/multiple/(?P<pks>([0-9]+/)+[0-9]+)/?$',
        trust_stores.TrustStoresMultipleDownloadView.as_view(),
        name='truststores-download'
    ),
    re_path(
        r'^truststores/download/multiple/'
        r'(?P<file_format>[a-zA-Z0-9_]+)/'
        r'(?P<archive_format>[a-zA-Z0-9_]+)/'
        r'(?P<pks>([0-9]+/)+[0-9]+)/?$',
        trust_stores.TrustStoresMultipleDownloadView.as_view(),
        name='truststores-file-download'
    ),
    re_path(
        r'^truststores/download/(?P<pk>[0-9]+)/?$',
        trust_stores.TrustStoresDownloadView.as_view(),
        name='truststore-download',
    ),
    re_path(
        r'^truststores/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?',
        trust_stores.TrustStoresDownloadView.as_view(),
        name='truststore-file-download',
    ),
    re_path(
        r'^truststores/delete/(?P<pks>([0-9]+/)+[0-9]*)/?$',
        trust_stores.TrustStoresBulkDeleteConfirmView.as_view(),
        name='truststores-delete_confirm',
    ),
    path('truststores/detail/<pk>/', trust_stores.TrustStoresDetailView.as_view(), name='truststore_details'),
]
