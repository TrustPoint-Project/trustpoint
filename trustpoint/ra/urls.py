from django.urls import path

from .views import DownloadCertificateView, OnboardingRequestView

urlpatterns = [
    path('onboarding-request/', OnboardingRequestView.as_view(), name='onboarding_request'),
    path('<int:device_id>/download_certificate/', DownloadCertificateView.as_view(), name='download_certificate'),
]
