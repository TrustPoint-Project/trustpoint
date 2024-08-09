"""URL configuration for the PKI application."""

from django.urls import path

from . import views

app_name = 'est'

urlpatterns = [
    path('<str:domain>/cacerts/', views.EstSimpleEnrollView.as_view()),
    # TODO: default domain
    path('simpleenroll/', views.EstSimpleEnrollView.as_view()),
    path('<str:domain>/simpleenroll/', views.EstSimpleEnrollView.as_view()),
    path('<str:domain>/simplereenroll/', views.EstSimpleEnrollView.as_view()),
    path('<str:domain>/fullcmc/', views.EstSimpleEnrollView.as_view()),
    path('<str:domain>/serverkeygen/', views.EstSimpleEnrollView.as_view()),
    path('<str:domain>/csrattrs/', views.EstSimpleEnrollView.as_view()),
]
