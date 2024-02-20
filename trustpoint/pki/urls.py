"""URL configuration for the PKI application."""


from django.urls import path, re_path

from . import views

app_name = 'pki'
urlpatterns = [
    path('', views.endpoint_profiles, name='index'),
    path('endpoint-profiles/', views.endpoint_profiles, name='endpoint_profiles'),
    path('issuing-certificate-authorities/', views.IssuingCaListView.as_view(), name='issuing_cas'),
    re_path(
        r'issuing-certificate-authorities/delete/(?P<issuing_cas>[1-9][0-9]*(?:/[1-9][0-9]*)*)',
        views.bulk_delete_issuing_cas,
        name='issuing_cas-delete',
    ),
    path(
        'issuing-certificate-authorities/add/local/file/',
        views.add_issuing_ca_local_file,
        name='issuing_cas-add_local_file',
    ),
    path(
        'issuing-certificate-authorities/add/local/request/',
        views.add_issuing_ca_local_request,
        name='issuing_cas-add_local_request',
    ),
    path(
        'issuing-certificate-authorities/add/remote/est/',
        views.add_issuing_ca_remote_est,
        name='issuing_cas-add_remote_est',
    ),
    path(
        'issuing-certificate-authorities/add/remote/cmp/',
        views.add_issuing_ca_remote_cmp,
        name='issuing_cas-add_remote_cmp',
    ),
    path('issuing-certificate-authorities/details/<int:pk>/', views.issuing_ca_detail, name='issuing_cas-details'),
]
