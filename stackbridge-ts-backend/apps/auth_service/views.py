from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.auth_service.serializers import RegisterSerializer
from apps.auth_service.services.registration_service import (
    DefaultRoleNotConfiguredError,
    EmailAlreadyExistsError,
    RegistrationError,
    register_user,
)


class RegistrationUnavailableError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "Registration is temporarily unavailable."
    default_code = "registration_unavailable"


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(
            data=request.data,
        )
        serializer.is_valid(raise_exception=True)

        registration_data = serializer.validated_data.copy()

        registration_data.pop("password_repeat")

        try:
            result = register_user(
                **registration_data,
            )
        except EmailAlreadyExistsError as error:
            raise ValidationError(
                {
                    "email": [
                        "A user with this email already exists."
                    ]
                }
            ) from error
        except DefaultRoleNotConfiguredError as error:
            raise RegistrationUnavailableError() from error
        except RegistrationError as error:
            raise RegistrationUnavailableError() from error

        return Response(
            {
                "id": str(result.user.id),
                "email": result.user.email,
                "is_active": result.user.is_active,
                "profile": {
                    "first_name": result.profile.first_name,
                    "last_name": result.profile.last_name,
                    "middle_name": result.profile.middle_name,
                },
                "roles": [
                    result.role_assignment.role.code,
                ],
                "created_at": result.user.created_at,
            },
            status=status.HTTP_201_CREATED,
        )