from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.access_service.services.permission_service import AccessDeniedError, check_permission
from apps.access_service.services.role_assignment_service import get_active_user_roles
from apps.auth_service.services.account_service import soft_delete_account
from apps.profile_service.serializers import ProfileUpdateSerializer, UserProfileSerializer
from apps.profile_service.services import update_profile


class ProfileMeView(APIView):
    permission_classes = [IsAuthenticated]

    def _require(self, request, action: str) -> None:
        try:
            check_permission(
                user=request.user,
                resource_code="profiles",
                action_code=action,
                object_owner_id=request.user.id,
            )
        except AccessDeniedError as error:
            raise PermissionDenied(str(error)) from error

    def _response_data(self, user) -> dict:
        return {
            "id": user.id,
            "email": user.email,
            "is_active": user.is_active,
            "profile": UserProfileSerializer(user.profile).data,
            "roles": list(get_active_user_roles(user=user).values_list("code", flat=True)),
        }

    def get(self, request) -> Response:
        self._require(request, "read")
        return Response(self._response_data(request.user))

    @extend_schema(request=ProfileUpdateSerializer, responses={200: dict})
    def patch(self, request) -> Response:
        self._require(request, "update")
        allowed = {"first_name", "last_name", "middle_name"}
        invalid = sorted(set(request.data) - allowed)
        if invalid:
            raise ValidationError({field: ["This field cannot be changed here."] for field in invalid})
        serializer = ProfileUpdateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        update_profile(profile=request.user.profile, **serializer.validated_data)
        request.user.refresh_from_db()
        return Response(self._response_data(request.user))

    @extend_schema(request=None, responses={204: None})
    def delete(self, request) -> Response:
        self._require(request, "delete")
        soft_delete_account(user=request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)
