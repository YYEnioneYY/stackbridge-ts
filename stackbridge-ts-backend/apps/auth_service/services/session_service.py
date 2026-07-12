import hmac
from dataclasses import dataclass
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone

from apps.auth_service.models import AuthSession, User
from apps.auth_service.services.token_service import (
    TokenPair, TokenValidationError, create_token_pair, hash_refresh_token, verify_refresh_token,
)


class SessionServiceError(Exception):
    pass


class InactiveUserError(SessionServiceError):
    pass


class InvalidSessionError(SessionServiceError):
    pass


class RefreshTokenReuseError(InvalidSessionError):
    pass


@dataclass(frozen=True)
class CreatedSession:
    session: AuthSession
    tokens: TokenPair


@transaction.atomic
def create_auth_session(*, user: User, user_agent: str = "", ip_address: str | None = None) -> CreatedSession:
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    if not locked_user.is_active or locked_user.deleted_at is not None:
        raise InactiveUserError("Cannot create a session for an inactive user.")
    session_id = uuid4()
    tokens = create_token_pair(user_id=locked_user.id, session_id=session_id)
    session = AuthSession.objects.create(
        id=session_id, user=locked_user, refresh_token_hash=hash_refresh_token(tokens.refresh_token),
        user_agent=user_agent.strip(), ip_address=ip_address, expires_at=tokens.refresh_expires_at,
    )
    locked_user.last_login_at = timezone.now()
    locked_user.save(update_fields=["last_login_at", "updated_at"])
    return CreatedSession(session=session, tokens=tokens)


def rotate_refresh_token(refresh_token: str) -> CreatedSession:
    try:
        payload = verify_refresh_token(refresh_token)
    except TokenValidationError as error:
        raise InvalidSessionError("Refresh token is invalid.") from error
    reused = False
    result = None
    with transaction.atomic():
        session = (
            AuthSession.objects.select_for_update().select_related("user")
            .filter(id=payload.session_id, user_id=payload.user_id).first()
        )
        if session is None or not session.user.is_active or session.user.deleted_at is not None:
            raise InvalidSessionError("Refresh session is invalid.")
        candidate_hash = hash_refresh_token(refresh_token)
        if not hmac.compare_digest(candidate_hash, session.refresh_token_hash):
            if session.revoked_at is None:
                session.revoked_at = timezone.now()
                session.save(update_fields=["revoked_at", "updated_at"])
            reused = True
        elif not session.is_active_session:
            raise InvalidSessionError("Refresh session is inactive.")
        else:
            tokens = create_token_pair(user_id=session.user_id, session_id=session.id)
            session.refresh_token_hash = hash_refresh_token(tokens.refresh_token)
            session.expires_at = tokens.refresh_expires_at
            session.save(update_fields=["refresh_token_hash", "expires_at", "updated_at"])
            result = CreatedSession(session=session, tokens=tokens)
    if reused:
        raise RefreshTokenReuseError("Refresh token reuse was detected.")
    if result is None:
        raise InvalidSessionError("Refresh session is invalid.")
    return result


@transaction.atomic
def revoke_session(session_id: UUID, user_id: UUID | None = None) -> bool:
    query = AuthSession.objects.select_for_update().filter(id=session_id)
    if user_id is not None:
        query = query.filter(user_id=user_id)
    session = query.first()
    if session is None:
        return False
    if session.revoked_at is None:
        session.revoked_at = timezone.now()
        session.save(update_fields=["revoked_at", "updated_at"])
    return True


@transaction.atomic
def revoke_all_sessions(*, user: User, except_session_id: UUID | None = None) -> int:
    sessions = AuthSession.objects.select_for_update().filter(user=user, revoked_at__isnull=True)
    if except_session_id is not None:
        sessions = sessions.exclude(id=except_session_id)
    return sessions.update(revoked_at=timezone.now(), updated_at=timezone.now())


def is_session_active(*, session_id: UUID, user_id: UUID) -> bool:
    session = AuthSession.objects.filter(id=session_id, user_id=user_id).first()
    return bool(session and session.is_active_session)
