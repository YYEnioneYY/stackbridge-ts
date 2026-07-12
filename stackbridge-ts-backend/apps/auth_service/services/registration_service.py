from dataclasses import dataclass

from django.db import IntegrityError, transaction

from apps.access_service.models import Role, UserRoleAssignment
from apps.auth_service.models import User
from apps.auth_service.services.password_service import hash_password
from apps.profile_service.models import UserProfile


class RegistrationError(Exception):
    pass


class EmailAlreadyExistsError(RegistrationError):
    pass


class DefaultRoleNotConfiguredError(RegistrationError):
    pass


@dataclass(frozen=True)
class RegistrationResult:
    user: User
    profile: UserProfile
    role_assignment: UserRoleAssignment


def register_user(
    *, email: str, password: str, first_name: str, last_name: str, middle_name: str = "",
) -> RegistrationResult:
    normalized_email = email.strip().lower()
    password_hash = hash_password(password)
    try:
        with transaction.atomic():
            default_role = Role.objects.select_for_update().filter(code="user", is_active=True).first()
            if default_role is None:
                raise DefaultRoleNotConfiguredError("The default user role is not configured.")
            user = User.objects.create(email=normalized_email, password_hash=password_hash)
            profile = UserProfile.objects.create(
                user=user,
                first_name=first_name.strip(),
                last_name=last_name.strip(),
                middle_name=middle_name.strip(),
            )
            assignment = UserRoleAssignment.objects.create(user=user, role=default_role)
    except IntegrityError as error:
        if User.objects.filter(email__iexact=normalized_email).exists():
            raise EmailAlreadyExistsError("A user with this email already exists.") from error
        raise RegistrationError("Failed to register the user.") from error
    return RegistrationResult(user=user, profile=profile, role_assignment=assignment)
