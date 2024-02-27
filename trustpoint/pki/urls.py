"""URL configuration for the PKI application."""


from django.urls import path, re_path

from . import views

app_name = 'pki'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('endpoint-profiles/', views.EndpointProfilesTemplateView.as_view(), name='endpoint_profiles'),
    path('issuing-certificate-authorities/', views.IssuingCaListView.as_view(), name='issuing_cas'),
    re_path(
        r'^issuing-certificate-authorities/delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.IssuingCaBulkDeleteView.as_view(),
        name='issuing_cas-delete',
    ),
    re_path(
        r'^issuing-certificate-authorities/delete/',
        views.IssuingCasRedirectView.as_view(),
        name='issuing_cas-redirect',
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
]
