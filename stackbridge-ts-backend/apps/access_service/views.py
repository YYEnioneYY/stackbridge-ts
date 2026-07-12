from uuid import UUID

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.access_service.models import AccessAction, AccessPolicy, AccessResource, Role, UserRoleAssignment
from apps.access_service.serializers import (
    ActionInputSerializer, ActionSerializer, PolicyInputSerializer, PolicySerializer,
    ResourceInputSerializer, ResourceSerializer, RoleAssignmentInputSerializer,
    RoleAssignmentSerializer, RoleInputSerializer, RoleSerializer,
)
from apps.access_service.services.access_object_service import (
    AccessObjectAlreadyExistsError, AccessObjectNotFoundError, AccessObjectServiceError,
    create_action, create_policy, create_resource, deactivate_policy, set_access_object_active,
    update_action, update_policy, update_resource,
)
from apps.access_service.services.permission_service import AccessDeniedError, check_any_permission
from apps.access_service.services.role_assignment_service import (
    AssignmentTargetNotFoundError, RoleAssignmentServiceError, assign_role, get_user_and_role, revoke_role,
)
from apps.access_service.services.role_service import (
    RoleAlreadyExistsError, RoleNotFoundError, RoleServiceError, activate_role,
    create_role, deactivate_role, update_role,
)
from apps.auth_service.models import User


class AuthenticatedAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def require(self, user: User, resource: str, *actions: str) -> None:
        try:
            check_any_permission(user=user, resource_code=resource, actions=tuple(actions))
        except AccessDeniedError as error:
            raise PermissionDenied(str(error)) from error


def _service_error(error: Exception) -> None:
    if isinstance(error, (RoleNotFoundError, AccessObjectNotFoundError, AssignmentTargetNotFoundError)):
        raise NotFound(str(error)) from error
    raise ValidationError({"non_field_errors": [str(error)]}) from error


def _require_fields(data: dict, fields: tuple[str, ...]) -> None:
    missing = {field: ["This field is required."] for field in fields if field not in data}
    if missing:
        raise ValidationError(missing)


class RoleListView(AuthenticatedAPIView):
    def get(self, request) -> Response:
        self.require(request.user, "roles", "read")
        return Response(RoleSerializer(Role.objects.order_by("code"), many=True).data)

    def post(self, request) -> Response:
        self.require(request.user, "roles", "create", "manage")
        serializer = RoleInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_fields(serializer.validated_data, ("code", "name"))
        try:
            role = create_role(**serializer.validated_data)
        except (RoleServiceError, RoleAlreadyExistsError) as error:
            _service_error(error)
        return Response(RoleSerializer(role).data, status=status.HTTP_201_CREATED)


class RoleDetailView(AuthenticatedAPIView):
    def get(self, request, role_id: UUID) -> Response:
        self.require(request.user, "roles", "read")
        return Response(RoleSerializer(get_object_or_404(Role, id=role_id)).data)

    def patch(self, request, role_id: UUID) -> Response:
        self.require(request.user, "roles", "update", "manage")
        serializer = RoleInputSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        try:
            role = update_role(role_id=role_id, **serializer.validated_data)
        except RoleServiceError as error:
            _service_error(error)
        return Response(RoleSerializer(role).data)


class RoleStateView(AuthenticatedAPIView):
    is_active = True

    def post(self, request, role_id: UUID) -> Response:
        self.require(request.user, "roles", "manage")
        try:
            role = activate_role(role_id=role_id) if self.is_active else deactivate_role(role_id=role_id)
        except RoleServiceError as error:
            _service_error(error)
        return Response(RoleSerializer(role).data)


class RoleActivateView(RoleStateView):
    is_active = True


class RoleDeactivateView(RoleStateView):
    is_active = False


class UserRoleListView(AuthenticatedAPIView):
    def get(self, request, user_id: UUID) -> Response:
        self.require(request.user, "user_roles", "read", "manage")
        get_object_or_404(User, id=user_id)
        assignments = UserRoleAssignment.objects.filter(user_id=user_id).select_related("role").order_by("-created_at")
        return Response(RoleAssignmentSerializer(assignments, many=True).data)

    def post(self, request, user_id: UUID) -> Response:
        self.require(request.user, "user_roles", "create", "manage")
        serializer = RoleAssignmentInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user, role = get_user_and_role(user_id=user_id, role_id=serializer.validated_data["role_id"])
            assignment = assign_role(user=user, role=role, assigned_by=request.user)
        except RoleAssignmentServiceError as error:
            _service_error(error)
        return Response(RoleAssignmentSerializer(assignment).data, status=status.HTTP_201_CREATED)


class UserRoleDetailView(AuthenticatedAPIView):
    def delete(self, request, user_id: UUID, role_id: UUID) -> Response:
        self.require(request.user, "user_roles", "delete", "manage")
        try:
            user, role = get_user_and_role(user_id=user_id, role_id=role_id)
            revoke_role(user=user, role=role, revoked_by=request.user)
        except RoleAssignmentServiceError as error:
            _service_error(error)
        return Response(status=status.HTTP_204_NO_CONTENT)


class AccessCollectionView(AuthenticatedAPIView):
    model = None
    output_serializer = None
    input_serializer = None
    resource_code = ""
    create_function = None

    def get(self, request) -> Response:
        self.require(request.user, self.resource_code, "read")
        return Response(self.output_serializer(self.model.objects.order_by("code"), many=True).data)

    def post(self, request) -> Response:
        self.require(request.user, self.resource_code, "create", "manage")
        serializer = self.input_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_fields(serializer.validated_data, ("code", "name"))
        try:
            instance = self.create_function(**serializer.validated_data)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(self.output_serializer(instance).data, status=status.HTTP_201_CREATED)


class AccessDetailView(AuthenticatedAPIView):
    model = None
    output_serializer = None
    input_serializer = None
    resource_code = ""
    update_function = None
    id_parameter = ""

    def get(self, request, object_id: UUID) -> Response:
        self.require(request.user, self.resource_code, "read")
        return Response(self.output_serializer(get_object_or_404(self.model, id=object_id)).data)

    def patch(self, request, object_id: UUID) -> Response:
        self.require(request.user, self.resource_code, "update", "manage")
        serializer = self.input_serializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        try:
            instance = self.update_function(**{self.id_parameter: object_id}, **serializer.validated_data)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(self.output_serializer(instance).data)


class ResourceListView(AccessCollectionView):
    model = AccessResource
    output_serializer = ResourceSerializer
    input_serializer = ResourceInputSerializer
    resource_code = "resources"
    create_function = staticmethod(create_resource)


class ResourceDetailView(AccessDetailView):
    model = AccessResource
    output_serializer = ResourceSerializer
    input_serializer = ResourceInputSerializer
    resource_code = "resources"
    update_function = staticmethod(update_resource)
    id_parameter = "resource_id"


class ActionListView(AccessCollectionView):
    model = AccessAction
    output_serializer = ActionSerializer
    input_serializer = ActionInputSerializer
    resource_code = "actions"
    create_function = staticmethod(create_action)


class ActionDetailView(AccessDetailView):
    model = AccessAction
    output_serializer = ActionSerializer
    input_serializer = ActionInputSerializer
    resource_code = "actions"
    update_function = staticmethod(update_action)
    id_parameter = "action_id"


class AccessObjectStateView(AuthenticatedAPIView):
    model = None
    output_serializer = None
    resource_code = ""
    is_active = True

    def post(self, request, object_id: UUID) -> Response:
        self.require(request.user, self.resource_code, "manage")
        try:
            instance = set_access_object_active(model=self.model, object_id=object_id, is_active=self.is_active)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(self.output_serializer(instance).data)


class ResourceActivateView(AccessObjectStateView):
    model = AccessResource
    output_serializer = ResourceSerializer
    resource_code = "resources"


class ResourceDeactivateView(ResourceActivateView):
    is_active = False


class ActionActivateView(AccessObjectStateView):
    model = AccessAction
    output_serializer = ActionSerializer
    resource_code = "actions"


class ActionDeactivateView(ActionActivateView):
    is_active = False


class PolicyListView(AuthenticatedAPIView):
    def get(self, request) -> Response:
        self.require(request.user, "policies", "read")
        policies = AccessPolicy.objects.select_related("role", "resource", "action").order_by("role__code", "resource__code", "action__code")
        for field in ("role", "resource", "action", "is_active"):
            value = request.query_params.get(field)
            if value is not None:
                lookup = f"{field}_id" if field != "is_active" else field
                if field == "is_active":
                    value = value.lower() in ("1", "true", "yes")
                policies = policies.filter(**{lookup: value})
        return Response(PolicySerializer(policies, many=True).data)

    def post(self, request) -> Response:
        self.require(request.user, "policies", "create", "manage")
        serializer = PolicyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_fields(serializer.validated_data, ("role_id", "resource_id", "action_id", "scope"))
        try:
            policy = create_policy(**serializer.validated_data)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(PolicySerializer(policy).data, status=status.HTTP_201_CREATED)


class PolicyDetailView(AuthenticatedAPIView):
    def get(self, request, policy_id: UUID) -> Response:
        self.require(request.user, "policies", "read")
        return Response(PolicySerializer(get_object_or_404(AccessPolicy, id=policy_id)).data)

    def patch(self, request, policy_id: UUID) -> Response:
        self.require(request.user, "policies", "update", "manage")
        serializer = PolicyInputSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        try:
            policy = update_policy(policy_id=policy_id, **serializer.validated_data)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(PolicySerializer(policy).data)

    def delete(self, request, policy_id: UUID) -> Response:
        self.require(request.user, "policies", "delete", "manage")
        try:
            deactivate_policy(policy_id=policy_id)
        except AccessObjectServiceError as error:
            _service_error(error)
        return Response(status=status.HTTP_204_NO_CONTENT)
