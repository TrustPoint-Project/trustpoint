from django.urls import path, re_path
from . import views


app_name = 'onboarding'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('manual/', views.onboarding_manual, name='manual'),
    path('manual/client', views.onboarding_manual_client, name='manual-client'),
    re_path(r'^api/trust-store/', views.trust_store, name='api-trust_store'),
    re_path(r'^api/ldevid/cert-chain/', views.cert_chain, name='api-cert_chain'),
    re_path(r'^api/ldevid/', views.ldevid, name='api-ldevid'),
    re_path(r'^api/state/', views.state, name='api-state'),
]
