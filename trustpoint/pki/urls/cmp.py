"""URL configuration for the PKI application."""

from django.urls import path

from ..views.pki_endpoints import cmp

app_name = 'cmp'

urlpatterns = [
    path('p/<str:domain>/initialization/', cmp.CmpInitializationRequestView.as_view()),
    # TODO: default domain
]
