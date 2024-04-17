"""URL configuration for the PKI application."""


from django.urls import path, re_path

from . import views

app_name = 'pki'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('endpoint-profiles/', views.EndpointProfilesListView.as_view(), name='endpoint_profiles'),
    re_path(
        r'^endpoint-profiles/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.EndpointProfilesBulkDeleteView.as_view(),
        name='issuing_cas-delete',
    ),
    re_path(
        r'^endpoint-profiles/delete/',
        views.EndpointProfilesRedirectView.as_view(),
        name='issuing_cas-redirect',
    ),
    path('endpoint-profiles/add/', views.CreateEndpointProfileView.as_view(), name='endpoint_profiles-add'),
    path(
        'endpoint-profiles/update/<int:pk>/', views.UpdateEndpointProfileView.as_view(), name='endpoint_profiles-update'
    ),
    path(
        'endpoint-profiles/details/<int:pk>/',
        views.EndpointProfilesDetailView.as_view(),
        name='endpoint_profiles-details',
    ),
    path('issuing-certificate-authorities/', views.IssuingCaListView.as_view(), name='issuing_cas'),
    re_path(
        r'^issuing-certificate-authorities/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.IssuingCaBulkDeleteView.as_view(),
        name='issuing_cas-delete',
    ),
    path(
        'issuing-certificate-authorities/add/local/file/',
        views.IssuingCaLocalFileMultiForms.as_view(),
        name='issuing_cas-add_local_file',
    ),
    path(
        'issuing-certificate-authorities/add/local/request/',
        views.AddIssuingCaLocalRequestTemplateView.as_view(),
        name='issuing_cas-add_local_request',
    ),
    path(
        'issuing-certificate-authorities/add/local/signed-ca/',
        views.AddIssuingCaLocalPki.as_view(),
        name='issuing_cas-add_local_signed_ca',
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
    path(
        'issuing-certificate-authorities/details/<int:pk>/',
        views.IssuingCaDetailView.as_view(),
        name='issuing_cas-details',
    ),
    path('root-certificate-authorities/', views.RootCaListView.as_view(), name='root_cas'),
    re_path(
        r'^root-certificate-authorities/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.RootCaBulkDeleteView.as_view(),
        name='root_cas-delete',
    ),
    path('root-certificate-authorities/add/',
         views.CreateRootCaView.as_view(),
         name='root_cas-add'),
    path(
        'root-certificate-authorities/details/<int:pk>/',
        views.RootCaDetailView.as_view(),
        name='root_cas-details',
    ),

]
