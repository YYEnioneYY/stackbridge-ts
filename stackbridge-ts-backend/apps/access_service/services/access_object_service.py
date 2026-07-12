from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.access_service.models import AccessAction, AccessPolicy, AccessResource, PolicyScope, Role


class AccessObjectServiceError(Exception):
    pass


class AccessObjectNotFoundError(AccessObjectServiceError):
    pass


class AccessObjectAlreadyExistsError(AccessObjectServiceError):
    pass


class InvalidAccessObjectError(AccessObjectServiceError):
    pass


def _clean_and_save(instance):
    try:
        instance.full_clean()
        instance.save()
    except ValidationError as error:
        raise InvalidAccessObjectError(getattr(error, "message_dict", str(error))) from error
    except IntegrityError as error:
        raise AccessObjectAlreadyExistsError("An object with this unique key already exists.") from error
    return instance


@transaction.atomic
def create_resource(*, code: str, name: str, description: str = "", has_owner: bool = False) -> AccessResource:
    return _clean_and_save(AccessResource(
        code=code.strip().lower(), name=name.strip(), description=description.strip(), has_owner=has_owner,
    ))


@transaction.atomic
def update_resource(*, resource_id: UUID, **changes) -> AccessResource:
    resource = AccessResource.objects.select_for_update().filter(id=resource_id).first()
    if resource is None:
        raise AccessObjectNotFoundError("Resource not found.")
    for field in ("code", "name", "description", "has_owner"):
        if field in changes:
            value = changes[field]
            if isinstance(value, str):
                value = value.strip().lower() if field == "code" else value.strip()
            setattr(resource, field, value)
    if not resource.has_owner and AccessPolicy.objects.filter(resource=resource, scope=PolicyScope.OWN, is_active=True).exists():
        raise InvalidAccessObjectError("A resource with active own policies must keep ownership enabled.")
    return _clean_and_save(resource)


@transaction.atomic
def create_action(*, code: str, name: str, description: str = "") -> AccessAction:
    return _clean_and_save(AccessAction(code=code.strip().lower(), name=name.strip(), description=description.strip()))


@transaction.atomic
def update_action(*, action_id: UUID, **changes) -> AccessAction:
    action = AccessAction.objects.select_for_update().filter(id=action_id).first()
    if action is None:
        raise AccessObjectNotFoundError("Action not found.")
    for field in ("code", "name", "description"):
        if field in changes:
            value = changes[field].strip()
            setattr(action, field, value.lower() if field == "code" else value)
    return _clean_and_save(action)


@transaction.atomic
def set_access_object_active(*, model, object_id: UUID, is_active: bool):
    instance = model.objects.select_for_update().filter(id=object_id).first()
    if instance is None:
        raise AccessObjectNotFoundError("Access object not found.")
    instance.is_active = is_active
    instance.save(update_fields=["is_active", "updated_at"])
    return instance


def _policy_relations(*, role_id: UUID, resource_id: UUID, action_id: UUID) -> tuple[Role, AccessResource, AccessAction]:
    role = Role.objects.filter(id=role_id).first()
    resource = AccessResource.objects.filter(id=resource_id).first()
    action = AccessAction.objects.filter(id=action_id).first()
    if role is None or resource is None or action is None:
        raise AccessObjectNotFoundError("Role, resource, or action not found.")
    return role, resource, action


@transaction.atomic
def create_policy(
    *, role_id: UUID, resource_id: UUID, action_id: UUID, scope: str, is_active: bool = True,
) -> AccessPolicy:
    role, resource, action = _policy_relations(role_id=role_id, resource_id=resource_id, action_id=action_id)
    return _clean_and_save(AccessPolicy(
        role=role, resource=resource, action=action, scope=scope, is_active=is_active,
    ))


@transaction.atomic
def update_policy(*, policy_id: UUID, **changes) -> AccessPolicy:
    policy = AccessPolicy.objects.select_for_update().filter(id=policy_id).first()
    if policy is None:
        raise AccessObjectNotFoundError("Policy not found.")
    role_id = changes.get("role_id", policy.role_id)
    resource_id = changes.get("resource_id", policy.resource_id)
    action_id = changes.get("action_id", policy.action_id)
    policy.role, policy.resource, policy.action = _policy_relations(
        role_id=role_id, resource_id=resource_id, action_id=action_id,
    )
    if "scope" in changes:
        policy.scope = changes["scope"]
    if "is_active" in changes:
        policy.is_active = changes["is_active"]
    return _clean_and_save(policy)


@transaction.atomic
def deactivate_policy(*, policy_id: UUID) -> AccessPolicy:
    policy = AccessPolicy.objects.select_for_update().filter(id=policy_id).first()
    if policy is None:
        raise AccessObjectNotFoundError("Policy not found.")
    policy.is_active = False
    policy.save(update_fields=["is_active", "updated_at"])
    return policy
