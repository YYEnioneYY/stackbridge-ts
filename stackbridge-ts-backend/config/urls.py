from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


urlpatterns = [
    path("api/auth/", include("apps.auth_service.urls")),
    path("api/profile/", include("apps.profile_service.urls")),
    path("api/access/", include("apps.access_service.urls")),
    path("api/business/", include("apps.business_service.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
]
