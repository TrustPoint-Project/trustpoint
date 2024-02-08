from django.urls import path
from . import views


app_name = 'onboarding'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('manual/', views.onboarding_manual, name='onboarding-manual'),
    path('manual/client', views.onboarding_manual_client, name='onboarding-manual-client'),
]
