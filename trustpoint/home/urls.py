from django.urls import path
from . import views


app_name = 'home'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('notifications/all/', views.AllNotificationsView.as_view(), name='all_notifications'),
    path('notifications/system/', views.SystemNotificationsView.as_view(), name='system_notifications'),
    path('notifications/certificate/', views.CertificateNotificationsView.as_view(), name='certificate_notifications'),
    path('notifications/domain/', views.DomainNotificationsView.as_view(), name='domain_notifications'),
    path('notifications/issuing_ca/', views.IssuingCaNotificationsView.as_view(), name='issuing_ca_notifications'),
    path('notifications/device/', views.DeviceNotificationsView.as_view(), name='device_notifications'),
    path('notifications/tabs/', views.notifications_with_tabs, name='notifications-tabs'),
    path('notification/<int:pk>/', views.notification_details_view, name='notification_details'),
]
