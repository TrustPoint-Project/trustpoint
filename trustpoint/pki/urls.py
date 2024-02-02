from django.urls import path
from . import views


urlpatterns = [
    path('', views.endpoint_profiles, name='pki'),
    path('endpoint-profiles/', views.endpoint_profiles, name='pki-ep'),
    path('certificate-authorities/', views.certificate_authorities, name='pki-ca'),
    path(
        'certifiate-authorities/add/local-issuing-ca/file/',
        views.add_ca_local_file,
        name='pki-ca-add-local-file'),
    path(
        'certifiate-authorities/add/local-issuing-ca/request/',
        views.add_ca_local_request,
        name='pki-ca-add-local-request'),
    path(
        'certifiate-authorities/add/remote-issuing-ca/est/',
        views.add_ca_remote_est,
        name='pki-ca-add-remote-est'),
    path(
        'certifiate-authorities/add/remote-issuing-ca/cmp/',
        views.add_ca_remote_cmp,
        name='pki-ca-add-remote-cmp'),
]
