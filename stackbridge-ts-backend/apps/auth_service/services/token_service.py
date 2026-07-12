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
    pass


class TokenExpiredError(TokenValidationError):
    pass


class TokenTypeError(TokenValidationError):
    pass


class TokenPayloadFormatError(TokenValidationError):
    pass


@dataclass(frozen=True)
class TokenPayload:
    user_id: UUID
    session_id: UUID
    token_type: str
    issued_at: datetime
    expires_at: datetime
    token_id: UUID | None = None


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime


def create_access_token(*, user_id: UUID, session_id: UUID) -> tuple[str, datetime]:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=settings.JWT_ACCESS_TTL_MINUTES)
    token = jwt.encode(
        {"sub": str(user_id), "sid": str(session_id), "type": ACCESS_TOKEN_TYPE, "iat": issued_at, "exp": expires_at},
        settings.JWT_ACCESS_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token, expires_at


def create_refresh_token(*, user_id: UUID, session_id: UUID) -> tuple[str, datetime]:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(days=settings.JWT_REFRESH_TTL_DAYS)
    token = jwt.encode(
        {
            "sub": str(user_id), "sid": str(session_id), "jti": str(uuid4()),
            "type": REFRESH_TOKEN_TYPE, "iat": issued_at, "exp": expires_at,
        },
        settings.JWT_REFRESH_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token, expires_at


def create_token_pair(*, user_id: UUID, session_id: UUID) -> TokenPair:
    access_token, access_expires_at = create_access_token(user_id=user_id, session_id=session_id)
    refresh_token, refresh_expires_at = create_refresh_token(user_id=user_id, session_id=session_id)
    return TokenPair(access_token, refresh_token, access_expires_at, refresh_expires_at)


def verify_access_token(token: str) -> TokenPayload:
    payload = _decode_token(token, settings.JWT_ACCESS_SECRET, ["sub", "sid", "type", "iat", "exp"])
    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenTypeError("Expected an access token.")
    return _build_token_payload(payload)


def verify_refresh_token(token: str) -> TokenPayload:
    payload = _decode_token(token, settings.JWT_REFRESH_SECRET, ["sub", "sid", "jti", "type", "iat", "exp"])
    if payload.get("type") != REFRESH_TOKEN_TYPE:
        raise TokenTypeError("Expected a refresh token.")
    return _build_token_payload(payload)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _decode_token(token: str, secret: str, required_claims: list[str]) -> dict[str, Any]:
    if not token:
        raise TokenValidationError("Token is required.")
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": required_claims},
        )
    except jwt.ExpiredSignatureError as error:
        raise TokenExpiredError("Token has expired.") from error
    except jwt.MissingRequiredClaimError as error:
        raise TokenPayloadFormatError("Token payload is incomplete.") from error
    except jwt.InvalidTokenError as error:
        raise TokenValidationError("Token is invalid.") from error


def _build_token_payload(payload: dict[str, Any]) -> TokenPayload:
    try:
        return TokenPayload(
            user_id=UUID(payload["sub"]),
            session_id=UUID(payload["sid"]),
            token_type=payload["type"],
            issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            token_id=UUID(payload["jti"]) if payload.get("jti") else None,
        )
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise TokenPayloadFormatError("Token payload has an invalid format.") from error
