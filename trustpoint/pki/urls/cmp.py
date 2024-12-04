"""URL configuration for the PKI application."""

# from django.urls import path, re_path
#
# from ..views.pki_endpoints import cmp

app_name = 'cmp'

urlpatterns = [
    # re_path(r'^p/(?P<domain>\w+)/initialization/?$', cmp.CmpInitializationRequestView.as_view()),
    # path('p/<str:domain>/initialization/', cmp.CmpInitializationRequestView.as_view())
    # path('p/<str:domain>/certification/', cmp.CmpCertificationRequestView.as_view()),
    # path('p/<str:domain>/keyupdate/', cmp.CmpKeyUpdateRequestView.as_view()),
    # path('p/<str:domain>/pkcs10/', cmp.CmpPkcs10RequestView.as_view()),
    # path('p/<str:domain>/revocation/', cmp.CmpRevocationRequestView.as_view()),
    # path('p/<str:domain>/getcacerts/', cmp.CmpGetCaCertsRequestView.as_view()),
    # path('p/<str:domain>/getrootupdate/', cmp.CmpGetRootUpdateRequestView.as_view()),
    # path('p/<str:domain>/getcertreqtemplate/', cmp.CmpGetCertReqTemplateRequestView.as_view()),
    # path('p/<str:domain>/getcrls/', cmp.CmpGetCrlsRequestView.as_view()),
]
