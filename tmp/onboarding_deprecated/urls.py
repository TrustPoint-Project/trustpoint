"""URL patterns for the onboarding app.

TODO Contains API endpoints as well, this should be moved to a separate API app managed by e.g. Django Ninja.
"""

from django.urls import path

from . import views

app_name = 'onboarding'
urlpatterns = [
    # path('<int:device_id>/', views.ManualOnboardingView.as_view(), name='manual-client'),
    # path('download/<int:device_id>/', views.ManualDownloadView.as_view(), name='manual-download'),
    # path('exit/<int:device_id>/', views.OnboardingExitView.as_view(), name='exit'),
    # path('revoke/<int:device_id>/', views.OnboardingRevocationView.as_view(), name='revoke'),
    # path('api/download/p12/<int:device_id>/', views.P12DownloadView.as_view(), name='api-p12-download'),
    # path('api/download/pem/<int:device_id>/', views.PemDownloadView.as_view(), name='pem-download'),
    # path('api/download/keystore/<int:device_id>/', views.JavaKeyStoreDownloadView.as_view(), name='keystore-download'),
    # path('browser/', views.BrowserLoginView.as_view(), name='browser-login')
]
