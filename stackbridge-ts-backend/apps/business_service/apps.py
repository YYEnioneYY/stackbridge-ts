from importlib import import_module

from django.apps import AppConfig


class BusinessServiceConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.business_service"

    def ready(self) -> None:
        import_module("apps.business_service.schema")
