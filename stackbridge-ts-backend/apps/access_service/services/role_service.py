from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.access_service.models import Role


class RoleServiceError(Exception):
    pass


class RoleNotFoundError(RoleServiceError):
    pass


class RoleAlreadyExistsError(RoleServiceError):
    pass


class SystemRoleModificationError(RoleServiceError):
    pass


class InvalidRoleDataError(RoleServiceError):
    pass


def normalize_role_code(code: str) -> str:
    normalized = code.strip().lower()
    if not normalized:
        raise InvalidRoleDataError("Role code cannot be empty.")
    return normalized


def create_role(*, code: str, name: str, description: str = "") -> Role:
    role = Role(code=normalize_role_code(code), name=name.strip(), description=description.strip())
    if not role.name:
        raise InvalidRoleDataError("Role name cannot be empty.")
    try:
        role.full_clean()
        with transaction.atomic():
            role.save()
    except ValidationError as error:
        raise InvalidRoleDataError(error.message_dict) from error
    except IntegrityError as error:
        raise RoleAlreadyExistsError("A role with this code already exists.") from error
    return role


@transaction.atomic
def update_role(*, role_id: UUID, code: str | None = None, name: str | None = None, description: str | None = None) -> Role:
    role = Role.objects.select_for_update().filter(id=role_id).first()
    if role is None:
        raise RoleNotFoundError("Role not found.")
    if code is not None:
        normalized = normalize_role_code(code)
        if role.is_system and normalized != role.code:
            raise SystemRoleModificationError("The code of a system role cannot be changed.")
        role.code = normalized
    if name is not None:
        if not name.strip():
            raise InvalidRoleDataError("Role name cannot be empty.")
        role.name = name.strip()
    if description is not None:
        role.description = description.strip()
    try:
        role.full_clean()
        role.save()
    except ValidationError as error:
        raise InvalidRoleDataError(getattr(error, "message_dict", str(error))) from error
    except IntegrityError as error:
        raise RoleAlreadyExistsError("A role with this code already exists.") from error
    return role


@transaction.atomic
def set_role_active(*, role_id: UUID, is_active: bool) -> Role:
    role = Role.objects.select_for_update().filter(id=role_id).first()
    if role is None:
        raise RoleNotFoundError("Role not found.")
    if role.is_system and not is_active:
        raise SystemRoleModificationError("A system role cannot be deactivated.")
    role.is_active = is_active
    role.save(update_fields=["is_active", "updated_at"])
    return role


def activate_role(*, role_id: UUID) -> Role:
    return set_role_active(role_id=role_id, is_active=True)


def deactivate_role(*, role_id: UUID) -> Role:
    return set_role_active(role_id=role_id, is_active=False)
