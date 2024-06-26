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
    ),
    path('issuing-cas/detail/<pk>/', views.IssuingCaDetailView.as_view(), name='issuing_cas-detail'),
    re_path(
        r'^issuing-cas/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.IssuingCaBulkDeleteConfirmView.as_view(),
        name='issuing_cas-delete_confirm',
    ),

    path('domain-profiles/', views.DomainProfileTableView.as_view(), name='domain_profiles'),
    path(
        'domain-profiles/add/',
        views.DomainProfileCreateView.as_view(),
        name='domain_profiles-add'
    ),
    path(
        'domain-profiles/edit/<pk>/',
        views.DomainProfileUpdateView.as_view(),
        name='domain_profiles-edit'
    ),
    path(
        'domain-profiles/detail/<pk>/',
        views.DomainProfileDetailView.as_view(),
        name='domain_profiles-delete_confirm'),
    re_path(
        r'^domain-profiles/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.DomainProfilesBulkDeleteConfirmView.as_view(),
        name='domain_profiles-delete_confirm',
    ),
]
