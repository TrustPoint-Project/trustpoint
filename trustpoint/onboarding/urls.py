"""URL patterns for the onboarding app.

TODO Contains API endpoints as well, this should be moved to a separate API app managed by e.g. Django Ninja.
"""

from django.urls import path, re_path

from . import views

app_name = 'onboarding'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('manual/', views.onboarding_manual, name='manual'),
    path('<int:device_id>/', views.onboarding_manual_client, name='manual-client'),
    path('cancel/<int:device_id>/', views.onboarding_cancel, name='cancel'),
    path('exit/<int:device_id>/', views.onboarding_exit, name='exit'),
    path('api/trust-store/<str:test>/', views.trust_store, name='api-trust_store'),
    re_path(r'^api/ldevid/cert-chain/', views.cert_chain, name='api-cert_chain'),
    re_path(r'^api/ldevid/', views.ldevid, name='api-ldevid'),
    re_path(r'^api/state/', views.state, name='api-state'),
]
