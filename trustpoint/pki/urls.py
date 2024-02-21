"""URL configuration for the PKI application."""


from django.urls import path, re_path

from . import views

app_name = 'pki'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('endpoint-profiles/', views.EndpointProfilesTemplateView.as_view(), name='endpoint_profiles'),
    path('issuing-certificate-authorities/', views.IssuingCaListView.as_view(), name='issuing_cas'),
    re_path(
        r'issuing-certificate-authorities/delete/(?P<issuing_cas>[1-9][0-9]*(?:/[1-9][0-9]*)*)',
        views.bulk_delete_issuing_cas,
        name='issuing_cas-delete',
    ),
    path(
        'issuing-certificate-authorities/add/local/file/',
        views.IssuingCaLocalFileMulti.as_view(),
        name='issuing_cas-add_local_file',
    ),
    path(
        'issuing-certificate-authorities/add/local/request/',
        views.AddIssuingCaLocalRequestTemplateView.as_view(),
        name='issuing_cas-add_local_request',
    ),
    path(
        'issuing-certificate-authorities/add/remote/est/',
        views.AddIssuingCaRemoteEstTemplateView.as_view(),
        name='issuing_cas-add_remote_est',
    ),
    path(
        'issuing-certificate-authorities/add/remote/cmp/',
        views.AddIssuingCaRemoteCmpTemplateView.as_view(),
        name='issuing_cas-add_remote_cmp',
    ),
    path('issuing-certificate-authorities/details/<int:pk>/', views.issuing_ca_detail, name='issuing_cas-details'),
]
