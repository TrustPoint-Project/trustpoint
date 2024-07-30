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
        'issuing-cas/add/file-import/file-type-select/',
        views.IssuingCaAddFileTypeSelectView.as_view(),
        name='issuing_cas-add-file_import-file_type_select'
    ),
    path(
        'issuing-cas/add/file-import/pkcs12',
        views.IssuingCaAddFileImportPkcs12View.as_view(),
        name='issuing_cas-add-file_import-pkcs12'
    ),
    path(
        'issuing-cas/add/file-import/other',
        views.IssuingCaAddFileImportOtherView.as_view(),
        name='issuing_cas-add-file_import-other'
    ),
    path('issuing-cas/detail/<pk>/', views.IssuingCaDetailView.as_view(), name='issuing_cas-detail'),
    re_path(
        r'^issuing-cas/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),
    path('ca-crl/<int:ca_id>/',
         views.CRLDownloadView.download_ca_crl,
         name='crl'),
    path('generate-ca-crl/<int:ca_id>/',
         views.CRLDownloadView.generate_ca_crl,
         name='crl'),
    path('domain-crl/<int:id>/',
         views.CRLDownloadView.download_domain_crl,
         name='crl'),
    path('generate-domain-crl/<int:id>/',
         views.CRLDownloadView.generate_domain_crl,
         name='crl'),
    path('domains/', views.DomainTableView.as_view(), name='domains'),
    path(
        'domains/add/',
        views.DomainCreateView.as_view(),
        name='domains-add'
    ),
    path(
        'domains/edit/<pk>/',
        views.DomainUpdateView.as_view(),
        name='domains-edit'
    ),
    path(
        'domains/detail/<pk>/',
        views.DomainDetailView.as_view(),
        name='domains-delete_confirm'),
    re_path(
        r'^domains/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.DomainBulkDeleteConfirmView.as_view(),
        name='domains-delete_confirm',
    ),
    path('truststores/', views.TrustStoresTableView.as_view(), name='truststores')
]
