"""URL configuration for the devices' application."""

from django.urls import path, re_path  # type: ignore[import-untyped]

from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='add'),
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name='details'),
    path('configure/<int:pk>/', views.DeviceConfigureView.as_view(), name='config'),
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name='clm'),
    path('certificate-lifecycle-management/issue-tls-client-credential/<int:pk>/',
        views.DeviceIssueTlsClientCredentialView.as_view(),
        name='issue_tls_client_credential'
    ),
    path('certificate-lifecycle-management/download-issued-application-credential/<int:pk>/<str:common_name>/<int:validity>/<str:format>',
        views.DeviceDownloadIssuedApplicationTlsClientCredential.as_view(),
        name='download_issued_application_credential'
    ),
    path(
        'certificate-lifecycle-management/download-issued-application-tls-client-credential/<int:pk>/',
        views.DeviceDownloadIssuedApplicationTlsClientCredential.as_view(),
        name='select_issued_application_tls_client_credential_format'
    ),
    path('certificate-lifecycle-management/issue-tls-server-credential/<int:pk>/',
         views.DeviceIssueTlsServerCredentialView.as_view(),
         name='issue_tls_server_credential'
         ),
    path(
        'certificate-lifecycle-management/successful_application_issuance/<int:pk>/',
        views.DeviceSuccessfulApplicationIssuanceRedirectView.as_view(),
        name='successful_application_issuance'
    ),
    path('onboarding/manual/<int:pk>/', views.ManualOnboardingView.as_view(), name='manual'),
    path(
        'onboarding/manual/<int:pk>/<str:format>/',
        views.ManualOnboardingDownloadView.as_view(),
        name='manual_download'),
    path(
        'onboarding/manual/summary/<int:pk>/',
        views.ManualOnboardingSummaryView.as_view(),
        name='manual_summary'),
]