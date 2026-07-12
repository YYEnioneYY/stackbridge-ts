from django.urls import path

from apps.access_service.views import (
    ActionActivateView, ActionDeactivateView, ActionDetailView, ActionListView,
    PolicyDetailView, PolicyListView, ResourceActivateView, ResourceDeactivateView,
    ResourceDetailView, ResourceListView, RoleActivateView, RoleDeactivateView,
    RoleDetailView, RoleListView, UserRoleDetailView, UserRoleListView,
)


urlpatterns = [
    path("roles/", RoleListView.as_view(), name="role-list"),
    path("roles/<uuid:role_id>/", RoleDetailView.as_view(), name="role-detail"),
    path("roles/<uuid:role_id>/activate/", RoleActivateView.as_view(), name="role-activate"),
    path("roles/<uuid:role_id>/deactivate/", RoleDeactivateView.as_view(), name="role-deactivate"),
    path("users/<uuid:user_id>/roles/", UserRoleListView.as_view(), name="user-role-list"),
    path("users/<uuid:user_id>/roles/<uuid:role_id>/", UserRoleDetailView.as_view(), name="user-role-detail"),
    path("resources/", ResourceListView.as_view(), name="resource-list"),
    path("resources/<uuid:object_id>/", ResourceDetailView.as_view(), name="resource-detail"),
    path("resources/<uuid:object_id>/activate/", ResourceActivateView.as_view(), name="resource-activate"),
    path("resources/<uuid:object_id>/deactivate/", ResourceDeactivateView.as_view(), name="resource-deactivate"),
    path("actions/", ActionListView.as_view(), name="action-list"),
    path("actions/<uuid:object_id>/", ActionDetailView.as_view(), name="action-detail"),
    path("actions/<uuid:object_id>/activate/", ActionActivateView.as_view(), name="action-activate"),
    path("actions/<uuid:object_id>/deactivate/", ActionDeactivateView.as_view(), name="action-deactivate"),
    path("policies/", PolicyListView.as_view(), name="policy-list"),
    path("policies/<uuid:policy_id>/", PolicyDetailView.as_view(), name="policy-detail"),
]
