from django.urls import path

from . import views

app_name = 'cmp'

urlpatterns = [
    path('initialization/', views.CmpInitializationRequestView.as_view()),
]
