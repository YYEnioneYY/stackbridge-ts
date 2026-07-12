from django.core.management.base import BaseCommand
from django.db import transaction

from apps.access_service.models import AccessAction, AccessPolicy, AccessResource, Role


ROLES = {
    "admin": ("Administrator", "Full system access."),
    "manager": ("Manager", "Business management access."),
    "user": ("User", "Default application access."),
}
RESOURCES = {
    "users": ("Users", False),
    "profiles": ("Profiles", True),
    "orders": ("Orders", True),
    "products": ("Products", False),
    "stores": ("Stores", False),
    "roles": ("Roles", False),
    "resources": ("Resources", False),
    "actions": ("Actions", False),
    "policies": ("Policies", False),
    "user_roles": ("User roles", False),
}
ACTIONS = {
    "read": "Read",
    "create": "Create",
    "update": "Update",
    "delete": "Delete",
    "manage": "Manage",
}
ROLE_POLICIES = {
    "manager": (
        ("profiles", "read", "own"), ("profiles", "update", "own"), ("profiles", "delete", "own"),
        ("orders", "read", "all"), ("orders", "create", "all"), ("orders", "update", "all"),
        ("orders", "delete", "all"), ("products", "read", "all"), ("stores", "read", "all"),
    ),
    "user": (
        ("profiles", "read", "own"), ("profiles", "update", "own"), ("profiles", "delete", "own"),
        ("orders", "read", "own"), ("orders", "create", "own"), ("orders", "update", "own"),
        ("orders", "delete", "own"), ("products", "read", "all"), ("stores", "read", "all"),
    ),
}


class Command(BaseCommand):
    help = "Creates or updates roles, resources, actions, and initial policies."

    @transaction.atomic
    def handle(self, *args, **options) -> None:
        roles = {}
        resources = {}
        actions = {}
        for code, (name, description) in ROLES.items():
            roles[code], _ = Role.objects.update_or_create(
                code=code,
                defaults={"name": name, "description": description, "is_system": True, "is_active": True},
            )
        for code, (name, has_owner) in RESOURCES.items():
            resources[code], _ = AccessResource.objects.update_or_create(
                code=code,
                defaults={"name": name, "description": "", "has_owner": has_owner, "is_active": True},
            )
        for code, name in ACTIONS.items():
            actions[code], _ = AccessAction.objects.update_or_create(
                code=code,
                defaults={"name": name, "description": "", "is_active": True},
            )
        for resource in resources.values():
            for action in actions.values():
                AccessPolicy.objects.update_or_create(
                    role=roles["admin"], resource=resource, action=action,
                    defaults={"scope": "all", "is_active": True},
                )
        for role_code, policies in ROLE_POLICIES.items():
            for resource_code, action_code, scope in policies:
                AccessPolicy.objects.update_or_create(
                    role=roles[role_code], resource=resources[resource_code], action=actions[action_code],
                    defaults={"scope": scope, "is_active": True},
                )
        self.stdout.write(self.style.SUCCESS("Access control seed completed."))
