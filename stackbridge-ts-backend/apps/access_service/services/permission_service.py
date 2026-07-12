from uuid import UUID

from apps.access_service.models import AccessPolicy, PolicyScope
from apps.auth_service.models import User


class AccessDeniedError(Exception):
    pass


_SCOPE_WEIGHT = {PolicyScope.NONE: 0, PolicyScope.OWN: 1, PolicyScope.ALL: 2}


def get_effective_scope(*, user: User, resource_code: str, action_code: str) -> str:
    if not user.is_active or user.deleted_at is not None:
        return PolicyScope.NONE
    scopes = AccessPolicy.objects.filter(
        is_active=True,
        resource__code=resource_code,
        resource__is_active=True,
        action__code=action_code,
        action__is_active=True,
        role__is_active=True,
        role__user_assignments__user=user,
        role__user_assignments__revoked_at__isnull=True,
    ).values_list("scope", flat=True)
    return max(scopes, key=lambda scope: _SCOPE_WEIGHT[scope], default=PolicyScope.NONE)


def check_permission(
    *, user: User, resource_code: str, action_code: str, object_owner_id: UUID | str | None = None,
) -> str:
    scope = get_effective_scope(user=user, resource_code=resource_code, action_code=action_code)
    if scope == PolicyScope.ALL:
        return scope
    if scope == PolicyScope.OWN and object_owner_id is not None and str(object_owner_id) == str(user.id):
        return scope
    raise AccessDeniedError("You do not have permission to perform this action.")


def check_any_permission(*, user: User, resource_code: str, actions: tuple[str, ...]) -> str:
    for action in actions:
        scope = get_effective_scope(user=user, resource_code=resource_code, action_code=action)
        if scope == PolicyScope.ALL:
            return scope
    raise AccessDeniedError("You do not have permission to perform this action.")
