from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.auth_service.serializers import LoginSerializer, RefreshSerializer, RegisterSerializer, TokenPairSerializer
from apps.auth_service.services.login_service import InvalidCredentialsError, login_user
from apps.auth_service.services.registration_service import (
    DefaultRoleNotConfiguredError, EmailAlreadyExistsError, RegistrationError, register_user,
)
from apps.auth_service.services.session_service import InvalidSessionError, revoke_all_sessions, revoke_session, rotate_refresh_token


class RegistrationUnavailableError(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Registration is temporarily unavailable."
    default_code = "registration_unavailable"


class InvalidCredentialsAPIError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Invalid email or password."
    default_code = "invalid_credentials"


class InvalidRefreshTokenAPIError(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Refresh token is invalid or inactive."
    default_code = "invalid_refresh_token"


def _token_response(tokens) -> dict:
    return {
        "access_token": tokens.access_token, "refresh_token": tokens.refresh_token, "token_type": "Bearer",
        "access_expires_at": tokens.access_expires_at, "refresh_expires_at": tokens.refresh_expires_at,
    }


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(request=RegisterSerializer, responses={201: dict})
    def post(self, request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data.copy()
        data.pop("password_repeat")
        try:
            result = register_user(**data)
        except EmailAlreadyExistsError as error:
            raise ValidationError({"email": ["A user with this email already exists."]}) from error
        except (DefaultRoleNotConfiguredError, RegistrationError) as error:
            raise RegistrationUnavailableError() from error
        return Response({
            "id": result.user.id, "email": result.user.email, "is_active": result.user.is_active,
            "profile": {
                "first_name": result.profile.first_name, "last_name": result.profile.last_name,
                "middle_name": result.profile.middle_name,
            },
            "roles": [result.role_assignment.role.code], "created_at": result.user.created_at,
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(request=LoginSerializer, responses={200: TokenPairSerializer})
    def post(self, request) -> Response:
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = login_user(
                **serializer.validated_data, user_agent=request.META.get("HTTP_USER_AGENT", ""),
                ip_address=request.META.get("REMOTE_ADDR"),
            )
        except InvalidCredentialsError as error:
            raise InvalidCredentialsAPIError() from error
        return Response(_token_response(result.tokens))


class RefreshView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(request=RefreshSerializer, responses={200: TokenPairSerializer})
    def post(self, request) -> Response:
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = rotate_refresh_token(serializer.validated_data["refresh_token"])
        except InvalidSessionError as error:
            raise InvalidRefreshTokenAPIError() from error
        return Response(_token_response(result.tokens))


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={204: None})
    def post(self, request) -> Response:
        revoke_session(request.auth.session_id, request.user.id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={204: None})
    def post(self, request) -> Response:
        revoke_all_sessions(user=request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)
