"""Routing configuration"""
from django.urls import path, re_path

from . import views

app_name = 'settings'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('language/', views.language, name='language'),
    path('logging/files/', views.LoggingFilesTableView.as_view(), name='logging-files'),
    re_path(
        r'^logging/files/details/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$',
        views.LoggingFilesDetailsView.as_view(),
        name='logging-files-details'),
    re_path(
        r'^logging/files/download/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$',
        views.LoggingFilesDownloadView.as_view(),
        name='logging-files-download'),
    re_path(
        r'^logging/files/download/(?P<archive_format>tar\.gz|zip)(?P<filenames>(?:/trustpoint\.log(\.\d{1,5})?)+)/?$',
        views.LoggingFilesDownloadMultipleView.as_view(),
        name='logging-files-download-multiple'),
    path('security/', views.security, name='security'),

]
