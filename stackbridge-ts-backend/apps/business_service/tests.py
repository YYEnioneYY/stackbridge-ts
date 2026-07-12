import pytest
from rest_framework.test import APIClient

from apps.access_service.models import Role
from apps.access_service.services.role_assignment_service import assign_role
from apps.auth_service.services.registration_service import register_user


pytestmark = pytest.mark.django_db


def login_client(user, password: str = "StrongPassword123!") -> APIClient:
    client = APIClient()
    response = client.post("/api/auth/login/", {"email": user.email, "password": password}, format="json")
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access_token']}")
    return client


def test_protected_endpoint_authentication_errors(api_client, seeded_db) -> None:
    assert api_client.get("/api/business/orders/").status_code == 401
    api_client.credentials(HTTP_AUTHORIZATION="Bearer invalid")
    assert api_client.get("/api/business/orders/").status_code == 401


def test_order_own_scope_filters_and_protects_objects(user, authenticated_client, seeded_db) -> None:
    other = register_user(
        email="other@example.com", password="StrongPassword123!", first_name="Other", last_name="User",
    ).user
    other_client = login_client(other)
    own_order = authenticated_client.post("/api/business/orders/", {"title": "Own", "status": "new"}, format="json")
    other_order = other_client.post("/api/business/orders/", {"title": "Other", "status": "new"}, format="json")
    assert own_order.status_code == 201
    assert other_order.status_code == 201
    listing = authenticated_client.get("/api/business/orders/")
    assert [item["id"] for item in listing.data] == [own_order.data["id"]]
    assert authenticated_client.get(f"/api/business/orders/{other_order.data['id']}/").status_code == 403


def test_manager_all_scope_reads_foreign_order(user, authenticated_client, seeded_db) -> None:
    other = register_user(
        email="manager-other@example.com", password="StrongPassword123!", first_name="Other", last_name="User",
    ).user
    other_client = login_client(other)
    order = other_client.post("/api/business/orders/", {"title": "Foreign", "status": "new"}, format="json")
    assign_role(user=user, role=Role.objects.get(code="manager"))
    response = authenticated_client.get(f"/api/business/orders/{order.data['id']}/")
    assert response.status_code == 200


def test_admin_api_requires_policy(user, authenticated_client, seeded_db) -> None:
    assert authenticated_client.get("/api/access/roles/").status_code == 403
    assign_role(user=user, role=Role.objects.get(code="admin"))
    response = authenticated_client.get("/api/access/roles/")
    assert response.status_code == 200


def test_admin_role_api_create_and_user_role_revoke(user, authenticated_client, seeded_db) -> None:
    assign_role(user=user, role=Role.objects.get(code="admin"))
    created = authenticated_client.post(
        "/api/access/roles/", {"code": "operator", "name": "Operator"}, format="json",
    )
    assert created.status_code == 201
    target = register_user(
        email="target@example.com", password="StrongPassword123!", first_name="Target", last_name="User",
    ).user
    assigned = authenticated_client.post(
        f"/api/access/users/{target.id}/roles/", {"role_id": created.data["id"]}, format="json",
    )
    assert assigned.status_code == 201
    revoked = authenticated_client.delete(f"/api/access/users/{target.id}/roles/{created.data['id']}/")
    assert revoked.status_code == 204


def test_ownerless_resource_never_accepts_own_scope(user, seeded_db) -> None:
    client = login_client(user)
    assert client.post("/api/business/products/", {"name": "New", "price": "10.00"}, format="json").status_code == 403
    assert client.get("/api/business/products/").status_code == 200
