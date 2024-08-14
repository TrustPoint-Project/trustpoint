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
    path(
        'certificates/download/<int:pk>/',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-download'),
    path(
        'certificates/download/<int:pk>/<str:file_format>/',
        certificates.CertificateDownloadView.as_view(),
        name='certificate-file-download'),
    re_path(
        r'^certificates/download/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        certificates.CertificateDownloadView.as_view(),
        name='certificates-file-download',
    ),
    path('certificates/detail/<int:pk>/', certificates.CertificateDetailView.as_view(), name='certificate-detail'),

    path('issuing-cas/', issuing_cas.IssuingCaTableView.as_view(), name='issuing_cas'),
    path(
        'issuing-cas/add/method-select/',
        issuing_cas.IssuingCaAddMethodSelectView.as_view(),
        name='issuing_cas-add-method_select'),
    path(
        'issuing-cas/add/file-import/file-type-select/',
        issuing_cas.IssuingCaAddFileTypeSelectView.as_view(),
        name='issuing_cas-add-file_import-file_type_select'
    ),
    path(
        'issuing-cas/add/file-import/pkcs12',
        issuing_cas.IssuingCaAddFileImportPkcs12View.as_view(),
        name='issuing_cas-add-file_import-pkcs12'
    ),
    path(
        'issuing-cas/add/file-import/other',
        issuing_cas.IssuingCaAddFileImportOtherView.as_view(),
        name='issuing_cas-add-file_import-other'
    ),
    path('issuing-cas/detail/<int:pk>/', issuing_cas.IssuingCaDetailView.as_view(), name='issuing_cas-detail'),
    re_path(
        r'^issuing-cas/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        issuing_cas.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),
    path('ca-crl/<int:ca_id>/',
         crls.CRLDownloadView.download_ca_crl,
         name='crl'),
    path('generate-ca-crl/<int:ca_id>/',
         crls.CRLDownloadView.generate_ca_crl,
         name='crl'),
    path('domain-crl/<int:id>/',
         crls.CRLDownloadView.download_domain_crl,
         name='crl'),
    path('generate-domain-crl/<int:id>/',
         crls.CRLDownloadView.generate_domain_crl,
         name='crl'),
    path('domains/', domains.DomainTableView.as_view(), name='domains'),
    path(
        'domains/add/',
        domains.DomainCreateView.as_view(),
        name='domains-add'
    ),
    path(
        'domains/edit/<int:pk>/',
        domains.DomainUpdateView.as_view(),
        name='domains-edit'
    ),
    path(
        'domains/detail/<int:pk>/',
        domains.DomainDetailView.as_view(),
        name='domains-delete_confirm'),
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
    )
]
