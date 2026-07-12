from django.urls import path

from apps.auth_service.views import RegisterView


app_name = "auth_service"


urlpatterns = [
    path(
        "register/",
        RegisterView.as_view(),
        name="register",
    ),
]