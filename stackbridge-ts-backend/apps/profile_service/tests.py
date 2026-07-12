import pytest

from apps.auth_service.models import AuthSession


pytestmark = pytest.mark.django_db


def test_profile_read_and_partial_update(authenticated_client, user) -> None:
    response = authenticated_client.get("/api/profile/me/")
    assert response.status_code == 200
    assert response.data["profile"]["full_name"] == "Ivanov Ivan"
    updated = authenticated_client.patch("/api/profile/me/", {"middle_name": "Ivanovich"}, format="json")
    assert updated.status_code == 200
    assert updated.data["profile"]["full_name"] == "Ivanov Ivan Ivanovich"


def test_profile_rejects_protected_fields(authenticated_client) -> None:
    response = authenticated_client.patch("/api/profile/me/", {"is_active": False}, format="json")
    assert response.status_code == 400


def test_account_deletion_is_soft_and_revokes_sessions(authenticated_client, user, api_client) -> None:
    response = authenticated_client.delete("/api/profile/me/")
    assert response.status_code == 204
    user.refresh_from_db()
    assert not user.is_active
    assert user.deleted_at is not None
    assert user.profile is not None
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    login = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    assert login.status_code == 401
