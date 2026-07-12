import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command

from apps.access_service.models import AccessAction, AccessPolicy, AccessResource, PolicyScope, Role, UserRoleAssignment
from apps.access_service.services.access_object_service import InvalidAccessObjectError, create_policy
from apps.access_service.services.permission_service import AccessDeniedError, check_permission, get_effective_scope
from apps.access_service.services.role_assignment_service import RoleAlreadyAssignedError, assign_role, revoke_role
from apps.access_service.services.role_service import SystemRoleModificationError, create_role, deactivate_role, update_role


pytestmark = pytest.mark.django_db


def test_seed_is_idempotent(db) -> None:
    call_command("seed_access_control", verbosity=0)
    counts = (Role.objects.count(), AccessResource.objects.count(), AccessAction.objects.count(), AccessPolicy.objects.count())
    call_command("seed_access_control", verbosity=0)
    assert counts == (Role.objects.count(), AccessResource.objects.count(), AccessAction.objects.count(), AccessPolicy.objects.count())
    assert counts[:3] == (3, 10, 5)


def test_custom_role_lifecycle_and_duplicate(seeded_db) -> None:
    role = create_role(code="auditor", name="Auditor")
    assert role.is_active
    with pytest.raises(Exception):
        create_role(code="auditor", name="Duplicate")
    assert not deactivate_role(role_id=role.id).is_active


def test_system_role_cannot_change_code_or_deactivate(seeded_db) -> None:
    role = Role.objects.get(code="admin")
    with pytest.raises(SystemRoleModificationError):
        update_role(role_id=role.id, code="root")
    with pytest.raises(SystemRoleModificationError):
        deactivate_role(role_id=role.id)
    with pytest.raises(ValidationError):
        role.delete()


def test_role_assignment_history_and_reassignment(user, seeded_db) -> None:
    role = Role.objects.get(code="manager")
    assignment = assign_role(user=user, role=role)
    with pytest.raises(RoleAlreadyAssignedError):
        assign_role(user=user, role=role)
    revoke_role(user=user, role=role, revoked_by=user)
    assignment.refresh_from_db()
    assert assignment.revoked_at is not None
    second = assign_role(user=user, role=role)
    assert second.id != assignment.id
    assert UserRoleAssignment.objects.filter(user=user, role=role).count() == 2


def test_permission_scope_strength_and_ownership(user, seeded_db) -> None:
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.OWN
    assert check_permission(user=user, resource_code="orders", action_code="read", object_owner_id=user.id) == PolicyScope.OWN
    with pytest.raises(AccessDeniedError):
        check_permission(user=user, resource_code="orders", action_code="read", object_owner_id=None)
    assignment = assign_role(user=user, role=Role.objects.get(code="manager"))
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.ALL
    assignment.revoke()
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.OWN


def test_inactive_role_and_policy_are_ignored(user, seeded_db) -> None:
    user_policy = AccessPolicy.objects.get(role__code="user", resource__code="orders", action__code="read")
    user_policy.is_active = False
    user_policy.save()
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.NONE
    custom_role = create_role(code="reader", name="Reader")
    assign_role(user=user, role=custom_role)
    create_policy(
        role_id=custom_role.id, resource_id=AccessResource.objects.get(code="orders").id,
        action_id=AccessAction.objects.get(code="read").id, scope="all",
    )
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.ALL
    deactivate_role(role_id=custom_role.id)
    assert get_effective_scope(user=user, resource_code="orders", action_code="read") == PolicyScope.NONE


def test_own_policy_rejected_for_ownerless_resource(seeded_db) -> None:
    with pytest.raises(InvalidAccessObjectError):
        create_policy(
            role_id=Role.objects.get(code="user").id,
            resource_id=AccessResource.objects.get(code="products").id,
            action_id=AccessAction.objects.get(code="create").id, scope="own",
        )


def test_absent_policy_denies(user, seeded_db) -> None:
    with pytest.raises(AccessDeniedError):
        check_permission(user=user, resource_code="roles", action_code="read")
