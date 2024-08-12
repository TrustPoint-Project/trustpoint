"""URL configuration for the PKI application."""

from django.urls import path

from ..views.pki_endpoints import est

app_name = 'est'

urlpatterns = [
    path('<str:domain>/cacerts/', est.EstSimpleEnrollView.as_view()),
    # TODO: default domain
    path('simpleenroll/', est.EstSimpleEnrollView.as_view()),
    path('<str:domain>/simpleenroll/', est.EstSimpleEnrollView.as_view()),
    path('<str:domain>/simplereenroll/', est.EstSimpleEnrollView.as_view()),
    path('<str:domain>/fullcmc/', est.EstSimpleEnrollView.as_view()),
    path('<str:domain>/serverkeygen/', est.EstSimpleEnrollView.as_view()),
    path('<str:domain>/csrattrs/', est.EstSimpleEnrollView.as_view()),
]
