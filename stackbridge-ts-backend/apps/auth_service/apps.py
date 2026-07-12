from importlib import import_module

from django.apps import AppConfig


class AuthServiceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.auth_service"

    def ready(self) -> None:
        import_module("apps.auth_service.schema")
        import_module("apps.access_service.schema")
        import_module("apps.profile_service.schema")
