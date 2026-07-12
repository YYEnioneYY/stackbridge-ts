from django.urls import path

from apps.profile_service.views import ProfileMeView


urlpatterns = [path("me/", ProfileMeView.as_view(), name="profile-me")]
