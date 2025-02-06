"""URL configuration for trustpoint project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/

Examples:
---------
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))

"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.utils import timezone
from django.views.decorators.http import last_modified
from django.views.decorators.vary import vary_on_cookie
from django.views.i18n import JavaScriptCatalog

from .views import base

last_modified_date = timezone.now()


if  settings.DEBUG:
    urlpatterns = [
        path('admin/', admin.site.urls)
    ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    urlpatterns = []

urlpatterns += [
    path('users/', include('users.urls')),
    path('setup-wizard/', include('setup_wizard.urls')),
    path('pki/', include('pki.urls')),
    path('.well-known/cmp/', include('cmp.urls')),
    path('home/', include('home.urls')),
    path('devices/', include('devices.urls')),
    path('settings/', include('settings.urls')),
    path('i18n/', include("django.conf.urls.i18n")),
    path(
        'jsi18n/',
        vary_on_cookie(
            last_modified(lambda req, **kw: last_modified_date)(
                JavaScriptCatalog.as_view()
        )),
        name='javascript-catalog'
    ),
    path('', base.IndexView.as_view()),
]
