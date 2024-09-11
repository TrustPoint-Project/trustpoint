from django.urls import path

from .views import LogDetailView, LogDownloadView, LogDownloadZipView, LogTableView

app_name = 'log'

urlpatterns = [
    path('', LogTableView.as_view(), name='logs'),
    path('view/<str:filename>/', LogDetailView.as_view(), name='log-detail'),
    path('download/<str:filename>/', LogDownloadView.as_view(), name='log-download'),
    path('download-multiple/', LogDownloadZipView.as_view(), name='log-download-multiple'),
]
