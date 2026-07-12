from dataclasses import dataclass
from uuid import uuid4

from django.db import transaction
from django.utils import timezone

from apps.auth_service.models import AuthSession, User
from apps.auth_service.services.token_service import (
    TokenPair,
    create_token_pair,
    hash_refresh_token,
)


class SessionCreationError(Exception):
    """Не удалось создать пользовательскую сессию."""


class InactiveUserError(SessionCreationError):
    """Нельзя создать сессию для неактивного пользователя."""


@dataclass(frozen=True)
class CreatedSession:
    session: AuthSession
    tokens: TokenPair


@transaction.atomic
def create_auth_session(
    *,
    user: User,
    user_agent: str = "",
    ip_address: str | None = None,
) -> CreatedSession:
    if not user.is_active or user.deleted_at is not None:
        raise InactiveUserError(
            "Cannot create a session for an inactive user."
        )

    session_id = uuid4()

    token_pair = create_token_pair(
        user_id=user.id,
        session_id=session_id,
    )

    session = AuthSession.objects.create(
        id=session_id,
        user=user,
        refresh_token_hash=hash_refresh_token(
            token_pair.refresh_token,
        ),
        user_agent=user_agent.strip(),
        ip_address=ip_address,
        expires_at=token_pair.refresh_expires_at,
    )

    user.last_login_at = timezone.now()
    user.save(
        update_fields=[
            "last_login_at",
            "updated_at",
        ]
    )

    return CreatedSession(
        session=session,
        tokens=token_pair,
    )