from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


class PasswordServiceError(Exception):
    """Базовая ошибка сервиса паролей."""


class PasswordHashingError(PasswordServiceError):
    """Не удалось создать хэш пароля."""


class InvalidPasswordHashError(PasswordServiceError):
    """В базе хранится повреждённый или неподдерживаемый хэш."""


@dataclass(frozen=True)
class PasswordVerificationResult:
    is_valid: bool
    new_password_hash: str | None = None


_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        return _password_hasher.hash(password)
    except HashingError as error:
        raise PasswordHashingError(
            "Failed to hash the password."
        ) from error


def verify_password(
    *,
    password: str,
    password_hash: str,
) -> bool:
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not isinstance(password_hash, str):
        raise TypeError("Password hash must be a string.")

    try:
        return _password_hasher.verify(
            password_hash,
            password,
        )
    except VerifyMismatchError:
        return False
    except InvalidHashError as error:
        raise InvalidPasswordHashError(
            "Stored password hash has an invalid format."
        ) from error
    except VerificationError as error:
        raise PasswordServiceError(
            "Password verification failed."
        ) from error


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _password_hasher.check_needs_rehash(
            password_hash
        )
    except InvalidHashError as error:
        raise InvalidPasswordHashError(
            "Stored password hash has an invalid format."
        ) from error


def verify_and_rehash_password(
    *,
    password: str,
    password_hash: str,
) -> PasswordVerificationResult:
    is_valid = verify_password(
        password=password,
        password_hash=password_hash,
    )

    if not is_valid:
        return PasswordVerificationResult(
            is_valid=False,
        )

    if password_needs_rehash(password_hash):
        return PasswordVerificationResult(
            is_valid=True,
            new_password_hash=hash_password(password),
        )

    return PasswordVerificationResult(
        is_valid=True,
    )