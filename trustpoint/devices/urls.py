"""URL configuration for the devices' application."""

from django.urls import path  # type: ignore[import-untyped]

from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='add'),
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name='details'),
    path('configure/<int:pk>/', views.DeviceConfigureView.as_view(), name='config'),
    path(
        'onboarding/<int:pk>/manual/issue-domain-credential/',
        views.DeviceManualOnboardingIssueDomainCredentialView.as_view(),
        name='manual_issue_domain_credential'),
    path('browser/', views.DeviceOnboardingBrowserLoginView.as_view(), name='browser_login'),
    path('browser/credential-download/<int:pk>/',
         views.DeviceBrowserCredentialDownloadView.as_view(),
         name='browser_domain_credential_download'),
    path(
        'credential-download/browser/<int:pk>/',
        views.DeviceBrowserOnboardingOTPView.as_view(),
        name='browser_otp_view'),
    path(
        'credential-download/browser/<int:pk>/cancel',
        views.DeviceBrowserOnboardingCancelView.as_view(),
        name='browser_cancel'),
    path(
        'credential-download/<int:pk>/',
        views.DeviceManualCredentialDownloadView.as_view(),
        name='domain_credential_download'),
    path(
        'certificate-lifecycle-management/<int:pk>/',
        views.DeviceCertificateLifecycleManagementSummaryView.as_view(),
        name='certificate_lifecycle_management'),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-client-credential/',
        views.DeviceIssueTlsClientCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_client_credential'),
    path(
        'certificate-lifecycle-management/<int:pk>/issue-tls-server-credential/',
        views.DeviceIssueTlsServerCredential.as_view(),
        name='certificate_lifecycle_management-issue_tls_server_credential'),
    path('certificate-lifecycle-management/<int:pk>/revoke/<int:credential_pk>/',
         views.DeviceRevocationView.as_view(),
         name='revocation_not_implemented'),
    path('revoke/<int:pk>/',
         views.DeviceRevocationView.as_view(),
         name='revocation_not_implemented'),
    path(
        'onboarding/<int:pk>/trustpoint-client/',
        views.TrustPointClientOnboardingSelectAuthenticationMethodView.as_view(),
        name='trustpoint_client_auth_method_select'),
    path(
        'onboarding/<int:pk>/trustpoint-client/password-based-mac/',
        views.TrustpointClientOnboardingPasswordBasedMacView.as_view(),
        name='trustpoint_client_password_based_mac'
    ),
    path(
        'onboarding/<int:pk>/trustpoint-client/cancel/',
        views.TrustpointClientCancelOnboardingProcessView.as_view(),
        name='trustpoint_client_cancel_onboarding_process'
    ),
    path('onboard-status/',
         views.DeviceOnboardStatusView.as_view(),
         name='device_onboard_status'
         ),
    path('onboarded/<int:pk>/',
         views.DeviceOnboardRedirectView.as_view(),
         name='device_onboard_redirect'),
]
