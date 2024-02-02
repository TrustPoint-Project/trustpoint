from django.urls import path
from . import views


urlpatterns = [
    path('', views.onboarding, name='onboarding'),
    path('manual/', views.onboarding_manual, name='onboarding-manual')
]
