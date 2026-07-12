from uuid import UUID

from django.db import IntegrityError, transaction

from apps.access_service.models import Role, UserRoleAssignment
from apps.auth_service.models import User


class RoleAssignmentServiceError(Exception):
    pass


class InactiveRoleError(RoleAssignmentServiceError):
    pass


class InactiveUserError(RoleAssignmentServiceError):
    pass


class RoleAlreadyAssignedError(RoleAssignmentServiceError):
    pass


class ActiveRoleAssignmentNotFoundError(RoleAssignmentServiceError):
    pass


class AssignmentTargetNotFoundError(RoleAssignmentServiceError):
    pass


@transaction.atomic
def assign_role(*, user: User, role: Role, assigned_by: User | None = None) -> UserRoleAssignment:
    locked_user = User.objects.select_for_update().filter(pk=user.pk).first()
    locked_role = Role.objects.select_for_update().filter(pk=role.pk).first()
    if locked_user is None or locked_role is None:
        raise AssignmentTargetNotFoundError("User or role not found.")
    if not locked_user.is_active or locked_user.deleted_at is not None:
        raise InactiveUserError("A role cannot be assigned to an inactive user.")
    if not locked_role.is_active:
        raise InactiveRoleError("An inactive role cannot be assigned.")
    try:
        return UserRoleAssignment.objects.create(user=locked_user, role=locked_role, assigned_by=assigned_by)
    except IntegrityError as error:
        raise RoleAlreadyAssignedError("The user already has this active role.") from error


@transaction.atomic
def revoke_role(*, user: User, role: Role, revoked_by: User) -> UserRoleAssignment:
    assignment = UserRoleAssignment.objects.select_for_update().filter(
        user=user, role=role, revoked_at__isnull=True,
    ).first()
    if assignment is None:
        raise ActiveRoleAssignmentNotFoundError("The user does not have this active role.")
    assignment.revoke(revoked_by=revoked_by)
    return assignment


def get_active_user_roles(*, user: User):
    return Role.objects.filter(
        is_active=True,
        user_assignments__user=user,
        user_assignments__revoked_at__isnull=True,
    ).distinct().order_by("code")


def get_user_and_role(*, user_id: UUID, role_id: UUID) -> tuple[User, Role]:
    user = User.objects.filter(id=user_id).first()
    role = Role.objects.filter(id=role_id).first()
    if user is None or role is None:
        raise AssignmentTargetNotFoundError("User or role not found.")
    return user, role
