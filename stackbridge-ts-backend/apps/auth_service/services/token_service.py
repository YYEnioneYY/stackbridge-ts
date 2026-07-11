import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import jwt
from django.conf import settings


ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


class TokenValidationError(Exception):
    """Базовая ошибка проверки JWT."""


class TokenExpiredError(TokenValidationError):
    """Срок действия JWT истёк."""


class TokenTypeError(TokenValidationError):
    """Передан JWT неправильного типа."""


@dataclass(frozen=True)
class TokenPayload:
    user_id: UUID
    session_id: UUID
    token_id: UUID
    token_type: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


def create_access_token(
    *,
    user_id: UUID,
    session_id: UUID,
) -> tuple[str, datetime]:
    expires_at = _utc_now() + timedelta(
        minutes=settings.JWT_ACCESS_TTL_MINUTES,
    )

    token = _create_token(
        user_id=user_id,
        session_id=session_id,
        token_type=ACCESS_TOKEN_TYPE,
        expires_at=expires_at,
        secret=settings.JWT_ACCESS_SECRET,
    )

    return token, expires_at


def create_refresh_token(
    *,
    user_id: UUID,
    session_id: UUID,
) -> tuple[str, datetime]:
    expires_at = _utc_now() + timedelta(
        days=settings.JWT_REFRESH_TTL_DAYS,
    )

    token = _create_token(
        user_id=user_id,
        session_id=session_id,
        token_type=REFRESH_TOKEN_TYPE,
        expires_at=expires_at,
        secret=settings.JWT_REFRESH_SECRET,
    )

    return token, expires_at


def create_token_pair(
    *,
    user_id: UUID,
    session_id: UUID,
) -> TokenPair:
    access_token, access_expires_at = create_access_token(
        user_id=user_id,
        session_id=session_id,
    )

    refresh_token, refresh_expires_at = create_refresh_token(
        user_id=user_id,
        session_id=session_id,
    )

    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
        refresh_expires_at=refresh_expires_at,
    )


def verify_access_token(token: str) -> TokenPayload:
    return _verify_token(
        token=token,
        expected_type=ACCESS_TOKEN_TYPE,
        secret=settings.JWT_ACCESS_SECRET,
    )


def verify_refresh_token(token: str) -> TokenPayload:
    return _verify_token(
        token=token,
        expected_type=REFRESH_TOKEN_TYPE,
        secret=settings.JWT_REFRESH_SECRET,
    )


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8"),
    ).hexdigest()


def _create_token(
    *,
    user_id: UUID,
    session_id: UUID,
    token_type: str,
    expires_at: datetime,
    secret: str,
) -> str:
    issued_at = _utc_now()

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "jti": str(uuid4()),
        "type": token_type,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
    }

    return jwt.encode(
        payload=payload,
        key=secret,
        algorithm=settings.JWT_ALGORITHM,
    )


def _verify_token(
    *,
    token: str,
    expected_type: str,
    secret: str,
) -> TokenPayload:
    if not token:
        raise TokenValidationError("Token is required.")

    try:
        payload: dict[str, Any] = jwt.decode(
            jwt=token,
            key=secret,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            leeway=settings.JWT_LEEWAY_SECONDS,
            options={
                "require": [
                    "sub",
                    "sid",
                    "jti",
                    "type",
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                ],
            },
        )
    except jwt.ExpiredSignatureError as error:
        raise TokenExpiredError(
            "Token has expired.",
        ) from error
    except jwt.InvalidTokenError as error:
        raise TokenValidationError(
            "Token is invalid.",
        ) from error

    token_type = payload.get("type")

    if token_type != expected_type:
        raise TokenTypeError(
            f"Expected {expected_type} token, "
            f"received {token_type!r}.",
        )

    try:
        return TokenPayload(
            user_id=UUID(payload["sub"]),
            session_id=UUID(payload["sid"]),
            token_id=UUID(payload["jti"]),
            token_type=token_type,
            issued_at=datetime.fromtimestamp(
                payload["iat"],
                tz=timezone.utc,
            ),
            expires_at=datetime.fromtimestamp(
                payload["exp"],
                tz=timezone.utc,
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise TokenValidationError(
            "Token payload has an invalid format.",
        ) from error


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)