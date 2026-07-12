import pytest


pytestmark = pytest.mark.django_db


def test_openapi_schema_lists_all_api_groups(api_client) -> None:
    response = api_client.get("/api/schema/")
    assert response.status_code == 200
    content = response.content.decode("utf-8")
    for path in (
        "/api/auth/login/", "/api/profile/me/", "/api/access/roles/", "/api/business/orders/",
    ):
        assert path in content
    assert "bearerAuth" in content


def test_swagger_ui_opens(api_client) -> None:
    assert api_client.get("/api/docs/").status_code == 200
