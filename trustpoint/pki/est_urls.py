"""URL configuration for the PKI application."""

from django.urls import path, re_path

from . import views

app_name = 'est'

urlpatterns = [
    path('<str:domain>/simpleenroll/', views.EstSimpleEnroll.as_view(), name='simple_enroll')
]
