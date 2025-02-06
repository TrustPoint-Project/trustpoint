from django.urls import path

from cmp import views

app_name = 'cmp'

urlpatterns = [
    path(
        'initialization/<str:domain>/',
        views.CmpInitializationRequestView.as_view(),
        name='initialization'
    ),
]
