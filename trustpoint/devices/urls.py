"""URL configuration for the devices' application."""

from django.urls import path, re_path  # type: ignore[import-untyped]

from . import views

app_name = 'devices'

urlpatterns = [
    path('', views.DeviceTableView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='add'),
    path('details/<int:pk>/', views.DeviceDetailsView.as_view(), name='details'),
    path('configure/<int:pk>/', views.DeviceConfigureView.as_view(), name='config'),
    path('onboarding/<int:pk>/manual/issue-domain-credential/', views.DeviceManualOnboardingIssueDomainCredentialView.as_view(), name='manual_issue_domain_credential'),
    path(
        'domain-credential-download/<int:pk>/',
        views.DeviceDomainCredentialDownloadView.as_view(),
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
    path(
        'application-credential-download/<int:pk>/',
        views.DeviceApplicationCredentialDownloadView.as_view(),
        name='application_credential_download'),
    path('certificate-lifecycle-management/<int:pk>/revoke/<int:credential_pk>/',
         views.DeviceCredentialRevocationView.as_view(),
         name='credential_revocation'),
    path('revoke/<int:pk>/',
         views.DeviceRevocationView.as_view(),
         name='device_revocation'),
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
    )
]