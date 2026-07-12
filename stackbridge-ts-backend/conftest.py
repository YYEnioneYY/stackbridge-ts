import pytest
from django.core.management import call_command
from rest_framework.test import APIClient

from apps.auth_service.services.registration_service import register_user


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def seeded_db(db):
    call_command("seed_access_control", verbosity=0)


@pytest.fixture
def user(seeded_db):
    return register_user(
        email="user@example.com", password="StrongPassword123!",
        first_name="Ivan", last_name="Ivanov",
    ).user


@pytest.fixture
def authenticated_client(api_client: APIClient, user):
    response = api_client.post(
        "/api/auth/login/", {"email": user.email, "password": "StrongPassword123!"}, format="json",
    )
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access_token']}")
    api_client.token_pair = response.data
    return api_client
