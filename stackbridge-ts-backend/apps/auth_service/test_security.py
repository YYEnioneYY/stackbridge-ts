from datetime import datetime, timedelta, timezone

import jwt
import pytest
from argon2 import PasswordHasher, Type
from django.conf import settings

from apps.auth_service.models import AuthSession


pytestmark = pytest.mark.django_db


def test_expired_access_token_returns_401(api_client, user) -> None:
    session = AuthSession.objects.create(
        user=user, refresh_token_hash="a" * 64,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(user.id), "sid": str(session.id), "type": "access",
            "iat": now - timedelta(minutes=2), "exp": now - timedelta(minutes=1),
        },
        settings.JWT_ACCESS_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    response = api_client.get("/api/profile/me/")
    assert response.status_code == 401
    assert response.data["error"]["code"] == "token_expired"


def test_login_rehashes_outdated_argon2_parameters(api_client, user) -> None:
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID)
    user.password_hash = weak_hasher.hash("StrongPassword123!")
    old_hash = user.password_hash
    user.save(update_fields=["password_hash", "updated_at"])
    response = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    assert response.status_code == 200
    user.refresh_from_db()
    assert user.password_hash != old_hash


def test_refresh_token_cannot_authenticate_protected_endpoint(api_client, user) -> None:
    response = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['refresh_token']}")
    assert api_client.get("/api/profile/me/").status_code == 401
