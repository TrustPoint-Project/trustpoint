from django.urls import path, re_path
from . import views


app_name = 'onboarding'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('manual/', views.onboarding_manual, name='onboarding-manual'),
    path('manual/client', views.onboarding_manual_client, name='onboarding-manual-client'),
    re_path(r'^trust-store/', views.trust_store, name='onboarding-trust-store'),
    re_path(r'^state/', views.state, name='onboarding-state'),
]
