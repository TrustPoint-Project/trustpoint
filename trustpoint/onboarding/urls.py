"""URL patterns for the onboarding app.

TODO Contains API endpoints as well, this should be moved to a separate API app managed by e.g. Django Ninja.
"""

from django.urls import path

from . import views

app_name = 'onboarding'
urlpatterns = [
    path('<int:device_id>/', views.ManualOnboardingView.as_view(), name='manual-client'),
    path('download/<int:device_id>/', views.ManualDownloadView.as_view(), name='manual-download'),
    path('exit/<int:device_id>/', views.OnboardingExitView.as_view(), name='exit'),
    path('revoke/<int:device_id>/', views.OnboardingRevocationView.as_view(), name='revoke'),
    # duplicate required due to trailing slash not being added automatically for POST and cURL requests
    path('api/trust-store/<str:url_ext>/', views.TrustStoreView.as_view(), name='api-trust_store'),
    path('api/trust-store/<str:url_ext>', views.TrustStoreView.as_view(), name='api-trust_store-noslash'),
    path('api/ldevid/cert-chain/<str:url_ext>/', views.CertChainView.as_view(), name='api-cert_chain'),
    path('api/ldevid/cert-chain/<str:url_ext>', views.CertChainView.as_view(), name='api-cert_chain-noslash'),
    path('api/ldevid/<str:url_ext>/', views.LDevIDView.as_view(), name='api-ldevid'),
    path('api/ldevid/<str:url_ext>', views.LDevIDView.as_view(), name='api-ldevid-noslash'),
    path('api/state/<str:url_ext>/', views.StateView.as_view(), name='api-state'),
    path('api/state/<str:url_ext>', views.StateView.as_view(), name='api-state-noslash'),
]
