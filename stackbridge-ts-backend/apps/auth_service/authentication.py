from dataclasses import dataclass
from uuid import UUID

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from apps.auth_service.models import AuthSession, User
from apps.auth_service.services.token_service import (
    TokenExpiredError, TokenPayload, TokenPayloadFormatError, TokenTypeError,
    TokenValidationError, verify_access_token,
)


class AccessTokenExpired(AuthenticationFailed):
    default_detail = "Access token has expired."
    default_code = "token_expired"


class InvalidAccessToken(AuthenticationFailed):
    default_detail = "Access token is invalid."
    default_code = "invalid_token"


@dataclass(frozen=True)
class AuthenticationContext:
    session_id: UUID
    payload: TokenPayload


class JWTAuthentication(BaseAuthentication):
    keyword = b"bearer"

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        if header[0].lower() != self.keyword or len(header) != 2:
            raise InvalidAccessToken()
        try:
            token = header[1].decode("utf-8")
        except UnicodeError as error:
            raise InvalidAccessToken() from error
        try:
            payload = verify_access_token(token)
        except TokenExpiredError as error:
            raise AccessTokenExpired() from error
        except (TokenValidationError, TokenTypeError, TokenPayloadFormatError) as error:
            raise InvalidAccessToken() from error
        session = AuthSession.objects.select_related("user").filter(
            id=payload.session_id, user_id=payload.user_id,
        ).first()
        if session is None or not session.is_active_session:
            raise InvalidAccessToken()
        user: User = session.user
        if not user.is_active or user.deleted_at is not None:
            raise InvalidAccessToken()
        return user, AuthenticationContext(session_id=session.id, payload=payload)

    def authenticate_header(self, request) -> str:
        return "Bearer"
