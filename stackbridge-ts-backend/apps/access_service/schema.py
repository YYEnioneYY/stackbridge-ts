from drf_spectacular.utils import extend_schema, extend_schema_view

from apps.access_service.serializers import (
    ActionInputSerializer, ActionSerializer, PolicyInputSerializer, PolicySerializer,
    ResourceInputSerializer, ResourceSerializer, RoleAssignmentInputSerializer,
    RoleAssignmentSerializer, RoleInputSerializer, RoleSerializer,
)
from apps.access_service.views import (
    ActionActivateView, ActionDeactivateView, ActionDetailView, ActionListView,
    PolicyDetailView, PolicyListView, ResourceActivateView, ResourceDeactivateView,
    ResourceDetailView, ResourceListView, RoleActivateView, RoleDeactivateView,
    RoleDetailView, RoleListView, UserRoleDetailView, UserRoleListView,
)


def configure(view, serializer, **operations) -> None:
    view.serializer_class = serializer
    extend_schema_view(**operations)(view)


configure(
    RoleListView, RoleSerializer,
    get=extend_schema(operation_id="access_roles_list", responses={200: RoleSerializer(many=True), 401: dict, 403: dict}),
    post=extend_schema(request=RoleInputSerializer, responses={201: RoleSerializer, 400: dict, 401: dict, 403: dict}),
)
configure(
    RoleDetailView, RoleSerializer,
    get=extend_schema(operation_id="access_roles_retrieve", responses={200: RoleSerializer, 401: dict, 403: dict, 404: dict}),
    patch=extend_schema(request=RoleInputSerializer, responses={200: RoleSerializer, 400: dict, 401: dict, 403: dict, 404: dict}),
)
for view in (RoleActivateView, RoleDeactivateView):
    configure(view, RoleSerializer, post=extend_schema(request=None, responses={200: RoleSerializer, 400: dict, 401: dict, 403: dict, 404: dict}))
configure(
    UserRoleListView, RoleAssignmentSerializer,
    get=extend_schema(responses={200: RoleAssignmentSerializer(many=True), 401: dict, 403: dict, 404: dict}),
    post=extend_schema(request=RoleAssignmentInputSerializer, responses={201: RoleAssignmentSerializer, 400: dict, 401: dict, 403: dict, 404: dict}),
)
configure(
    UserRoleDetailView, RoleAssignmentSerializer,
    delete=extend_schema(request=None, responses={204: None, 400: dict, 401: dict, 403: dict, 404: dict}),
)
configure(
    ResourceListView, ResourceSerializer,
    get=extend_schema(operation_id="access_resources_list", responses={200: ResourceSerializer(many=True), 401: dict, 403: dict}),
    post=extend_schema(request=ResourceInputSerializer, responses={201: ResourceSerializer, 400: dict, 401: dict, 403: dict}),
)
configure(
    ResourceDetailView, ResourceSerializer,
    get=extend_schema(operation_id="access_resources_retrieve", responses={200: ResourceSerializer, 401: dict, 403: dict, 404: dict}),
    patch=extend_schema(request=ResourceInputSerializer, responses={200: ResourceSerializer, 400: dict, 401: dict, 403: dict, 404: dict}),
)
for view in (ResourceActivateView, ResourceDeactivateView):
    configure(view, ResourceSerializer, post=extend_schema(request=None, responses={200: ResourceSerializer, 401: dict, 403: dict, 404: dict}))
configure(
    ActionListView, ActionSerializer,
    get=extend_schema(operation_id="access_actions_list", responses={200: ActionSerializer(many=True), 401: dict, 403: dict}),
    post=extend_schema(request=ActionInputSerializer, responses={201: ActionSerializer, 400: dict, 401: dict, 403: dict}),
)
configure(
    ActionDetailView, ActionSerializer,
    get=extend_schema(operation_id="access_actions_retrieve", responses={200: ActionSerializer, 401: dict, 403: dict, 404: dict}),
    patch=extend_schema(request=ActionInputSerializer, responses={200: ActionSerializer, 400: dict, 401: dict, 403: dict, 404: dict}),
)
for view in (ActionActivateView, ActionDeactivateView):
    configure(view, ActionSerializer, post=extend_schema(request=None, responses={200: ActionSerializer, 401: dict, 403: dict, 404: dict}))
configure(
    PolicyListView, PolicySerializer,
    get=extend_schema(operation_id="access_policies_list", responses={200: PolicySerializer(many=True), 401: dict, 403: dict}),
    post=extend_schema(request=PolicyInputSerializer, responses={201: PolicySerializer, 400: dict, 401: dict, 403: dict}),
)
configure(
    PolicyDetailView, PolicySerializer,
    get=extend_schema(operation_id="access_policies_retrieve", responses={200: PolicySerializer, 401: dict, 403: dict, 404: dict}),
    patch=extend_schema(request=PolicyInputSerializer, responses={200: PolicySerializer, 400: dict, 401: dict, 403: dict, 404: dict}),
    delete=extend_schema(request=None, responses={204: None, 401: dict, 403: dict, 404: dict}),
)
