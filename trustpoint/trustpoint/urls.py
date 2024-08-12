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

from . import api, views

last_modified_date = timezone.now()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', api.api.urls),
    path('users/', include('users.urls')),
    path('pki/', include('pki.urls.pki')),
    path('.well-known/est/', include('pki.urls.est')),
    path('.well-known/cmp/', include('pki.urls.cmp')),
    path('home/', include('home.urls')),
    path('devices/', include('devices.urls')),
    path('onboarding/', include('onboarding.urls')),
    path('sysconf/', include('sysconf.urls')),
    path('i18n/', include("django.conf.urls.i18n")),
    path(
        'jsi18n/',
        vary_on_cookie(
            last_modified(lambda req, **kw: last_modified_date)(
                JavaScriptCatalog.as_view()
        )),
        name='javascript-catalog'
    ),
    path('', views.IndexView.as_view()),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
