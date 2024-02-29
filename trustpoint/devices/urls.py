from django.urls import path, re_path
from . import views


app_name = 'devices'
urlpatterns = [
    path('', views.DeviceListView.as_view(), name='devices'),
    path('add/', views.CreateDeviceView.as_view(), name='devices-add'),
    path('update/<int:pk>/', views.UpdateDeviceView.as_view(),
         name='devices-update'),
    path('details/<int:pk>/', views.DeviceDetailView.as_view()),
    re_path(
        r'^delete/(?P<pks>[1-9][0-9]*(?:/[1-9][0-9]*)*)/?$',
        views.DevicesBulkDeleteView.as_view(),
        name='devices-delete',
    ),
    re_path(
        r'^delete/',
        views.DeviceListView.as_view(),
        name='devices-redirect',
    ),
]
