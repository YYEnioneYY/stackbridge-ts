from drf_spectacular.extensions import OpenApiAuthenticationExtension


class JWTAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "apps.auth_service.authentication.JWTAuthentication"
    name = "bearerAuth"

    def get_security_definition(self, auto_schema) -> dict:
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
