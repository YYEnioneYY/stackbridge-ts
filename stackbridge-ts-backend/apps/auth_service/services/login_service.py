from dataclasses import dataclass

from django.db import transaction

from apps.auth_service.models import User
from apps.auth_service.services.password_service import PasswordServiceError, hash_password, verify_and_rehash_password, verify_password
from apps.auth_service.services.session_service import CreatedSession, create_auth_session


class InvalidCredentialsError(Exception):
    pass


_DUMMY_PASSWORD_HASH = hash_password("invalid-credentials-timing-value")


@transaction.atomic
def login_user(*, email: str, password: str, user_agent: str = "", ip_address: str | None = None) -> CreatedSession:
    user = User.objects.select_for_update().filter(email__iexact=email.strip().lower()).first()
    if user is None:
        verify_password(password=password, password_hash=_DUMMY_PASSWORD_HASH)
        raise InvalidCredentialsError("Invalid email or password.")
    if not user.is_active or user.deleted_at is not None:
        raise InvalidCredentialsError("Invalid email or password.")
    try:
        verification = verify_and_rehash_password(password=password, password_hash=user.password_hash)
    except PasswordServiceError as error:
        raise InvalidCredentialsError("Invalid email or password.") from error
    if not verification.is_valid:
        raise InvalidCredentialsError("Invalid email or password.")
    if verification.new_password_hash:
        user.password_hash = verification.new_password_hash
        user.save(update_fields=["password_hash", "updated_at"])
    return create_auth_session(user=user, user_agent=user_agent, ip_address=ip_address)
