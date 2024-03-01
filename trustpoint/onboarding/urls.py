"""URL patterns for the onboarding app.

TODO Contains API endpoints as well, this should be moved to a separate API app managed by e.g. Django Ninja.
"""

from django.urls import path

from . import views

app_name = 'onboarding'
urlpatterns = [
    path('<int:device_id>/', views.onboarding_manual, name='manual-client'),
    path('exit/<int:device_id>/', views.onboarding_exit, name='exit'),
    path('api/trust-store/<str:url_ext>/', views.trust_store, name='api-trust_store'),
    path('api/ldevid/cert-chain/<str:url_ext>/', views.cert_chain, name='api-cert_chain'),
    # duplicate required due to trailing slash not being added automatically for POST requests
    path('api/ldevid/<str:url_ext>/', views.ldevid, name='api-ldevid'),
    path('api/ldevid/<str:url_ext>', views.ldevid, name='api-ldevid-noslash'),
    path('api/state/<str:url_ext>/', views.state, name='api-state'),
]
