import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.access_service.models import Role, UserRoleAssignment
from apps.auth_service.models import AuthSession, User
from apps.auth_service.services.password_service import verify_password
from apps.auth_service.services.token_service import TokenTypeError, hash_refresh_token, verify_access_token, verify_refresh_token
from apps.profile_service.models import UserProfile


pytestmark = pytest.mark.django_db


def registration_payload(**changes) -> dict:
    data = {
        "email": "  New.User@Example.COM ", "password": "StrongPassword123!",
        "password_repeat": "StrongPassword123!", "first_name": "New", "last_name": "User",
    }
    data.update(changes)
    return data


def test_registration_creates_complete_identity(api_client, seeded_db) -> None:
    response = api_client.post("/api/auth/register/", registration_payload(), format="json")
    assert response.status_code == 201
    user = User.objects.get(email="new.user@example.com")
    assert verify_password(password="StrongPassword123!", password_hash=user.password_hash)
    assert user.password_hash.startswith("$argon2id$")
    assert UserProfile.objects.filter(user=user, middle_name="").exists()
    assert UserRoleAssignment.objects.filter(user=user, role__code="user", revoked_at__isnull=True).exists()
    assert not hasattr(user, "password_repeat")


def test_registration_validation_and_duplicate_email(api_client, seeded_db) -> None:
    assert api_client.post("/api/auth/register/", registration_payload(), format="json").status_code == 201
    duplicate = api_client.post(
        "/api/auth/register/", registration_payload(email="NEW.USER@example.com"), format="json",
    )
    mismatch = api_client.post(
        "/api/auth/register/", registration_payload(password_repeat="different-password"), format="json",
    )
    missing = api_client.post("/api/auth/register/", {"email": "x@example.com"}, format="json")
    assert duplicate.status_code == 400
    assert mismatch.status_code == 400
    assert missing.status_code == 400
    assert duplicate.data["error"]["code"] == "validation_error"


def test_registration_rolls_back_without_default_role(api_client, db) -> None:
    response = api_client.post("/api/auth/register/", registration_payload(), format="json")
    assert response.status_code == 503
    assert User.objects.count() == 0
    assert UserProfile.objects.count() == 0


def test_login_creates_hashed_session_and_updates_user(api_client, user) -> None:
    response = api_client.post(
        "/api/auth/login/", {"email": "USER@EXAMPLE.COM", "password": "StrongPassword123!"},
        format="json", HTTP_USER_AGENT="pytest", REMOTE_ADDR="127.0.0.1",
    )
    assert response.status_code == 200
    session = AuthSession.objects.get(user=user)
    assert session.refresh_token_hash == hash_refresh_token(response.data["refresh_token"])
    assert session.refresh_token_hash != response.data["refresh_token"]
    assert len(session.refresh_token_hash) == 64
    assert session.user_agent == "pytest"
    user.refresh_from_db()
    assert user.last_login_at is not None
    assert verify_access_token(response.data["access_token"]).session_id == session.id


@pytest.mark.parametrize("email,password", [
    ("missing@example.com", "StrongPassword123!"),
    ("user@example.com", "WrongPassword123!"),
])
def test_login_hides_credential_reason(api_client, user, email: str, password: str) -> None:
    response = api_client.post("/api/auth/login/", {"email": email, "password": password}, format="json")
    assert response.status_code == 401
    assert response.data["error"]["code"] == "invalid_credentials"


@pytest.mark.parametrize("deleted", [False, True])
def test_inactive_or_deleted_user_cannot_login(api_client, user, deleted: bool) -> None:
    user.is_active = False
    if deleted:
        user.deleted_at = timezone.now()
    user.save()
    response = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    assert response.status_code == 401


def test_token_types_are_separated(authenticated_client) -> None:
    tokens = authenticated_client.token_pair
    with pytest.raises(Exception):
        verify_access_token(tokens["refresh_token"])
    with pytest.raises(Exception):
        verify_refresh_token(tokens["access_token"])


def test_refresh_rotates_and_reuse_revokes_session(api_client, user) -> None:
    login = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    old_refresh = login.data["refresh_token"]
    rotated = api_client.post("/api/auth/refresh/", {"refresh_token": old_refresh}, format="json")
    assert rotated.status_code == 200
    assert rotated.data["refresh_token"] != old_refresh
    reused = api_client.post("/api/auth/refresh/", {"refresh_token": old_refresh}, format="json")
    assert reused.status_code == 401
    session = AuthSession.objects.get(user=user)
    assert session.revoked_at is not None
    second = api_client.post("/api/auth/refresh/", {"refresh_token": rotated.data["refresh_token"]}, format="json")
    assert second.status_code == 401


def test_logout_immediately_invalidates_access(authenticated_client, user) -> None:
    response = authenticated_client.post("/api/auth/logout/")
    assert response.status_code == 204
    assert AuthSession.objects.get(user=user).revoked_at is not None
    assert authenticated_client.get("/api/profile/me/").status_code == 401


def test_logout_all_revokes_every_session(api_client, user) -> None:
    tokens = []
    for _ in range(2):
        response = api_client.post(
            "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
        )
        tokens.append(response.data)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens[0]['access_token']}")
    assert api_client.post("/api/auth/logout-all/").status_code == 204
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0


def test_create_initial_admin_command(seeded_db) -> None:
    call_command(
        "create_initial_admin", email="ADMIN@EXAMPLE.COM", password="StrongPassword123!",
        first_name="Admin", last_name="User", middle_name="",
    )
    admin = User.objects.get(email="admin@example.com")
    assert admin.profile.first_name == "Admin"
    assert UserRoleAssignment.objects.filter(user=admin, role__code="admin", revoked_at__isnull=True).exists()
