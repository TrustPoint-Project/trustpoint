from django.urls import path, re_path
from . import views


urlpatterns = [
    path('', views.endpoint_profiles, name='pki'),
    path('endpoint-profiles/', views.endpoint_profiles, name='pki-ep'),
    path('issuing-certificate-authorities/', views.IssuingCaListView.as_view(), name='pki-issuing_ca'),
    re_path(
        r'issuing-certificate-authorities/delete/(?P<issuing_cas>[1-9][0-9]*(?:/[1-9][0-9]*)*)',
        views.bulk_delete_issuing_cas,
        name='pki-issuing_ca-bulk_delete'
    ),
    path(
        'issuing-certificate-authorities/add/local/file/',
        views.add_issuing_ca_local_file,
        name='pki-issuing_ca-add-local-file'),
    path(
        'issuing-certificate-authorities/add/local/request/',
        views.add_issuing_ca_local_request,
        name='pki-issuing_ca-add-local-request'),
    path(
        'issuing-certificate-authorities/add/remote/est/',
        views.add_issuing_ca_remote_est,
        name='pki-issuing_ca-add-remote-est'),
    path(
        'issuing-certificate-authorities/add/remote/cmp/',
        views.add_issuing_ca_remote_cmp,
        name='pki-issuing_ca-add-remote-cmp'),
    path(
        'issuing-certificate-authorities/details/<int:pk>/',
        views.issuing_ca_detail,
        name='pki-issuing_ca-details')
]
