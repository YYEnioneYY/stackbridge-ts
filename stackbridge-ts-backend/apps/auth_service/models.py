from typing import Any

from django.db import models
from django.db.models import F, Q
from django.db.models.functions import Lower
from django.utils import timezone

from apps.common.models import BaseModel


class User(BaseModel):
    email = models.EmailField(max_length=255)
    password_hash = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "auth_users"
        constraints = [
            models.UniqueConstraint(Lower("email"), name="auth_users_email_lower_unique"),
            models.CheckConstraint(
                condition=Q(deleted_at__isnull=True) | Q(is_active=False),
                name="auth_users_deleted_at_requires_inactive",
            ),
        ]
        indexes = [
            models.Index(fields=["is_active"], name="auth_users_is_active_idx"),
            models.Index(fields=["deleted_at"], name="auth_users_deleted_at_idx"),
            models.Index(fields=["created_at"], name="auth_users_created_at_idx"),
        ]

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def soft_delete(self) -> None:
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save(update_fields=["is_active", "deleted_at", "updated_at"])

    def __str__(self) -> str:
        return self.email


class AuthSession(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sessions")
    refresh_token_hash = models.CharField(max_length=64, unique=True)
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "auth_sessions"
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="auth_sessions_expires_after_created",
            ),
            models.CheckConstraint(
                condition=Q(revoked_at__isnull=True) | Q(revoked_at__gte=F("created_at")),
                name="auth_sessions_revoke_time",
            ),
        ]
        indexes = [
            models.Index(fields=["user"], name="auth_sessions_user_idx"),
            models.Index(fields=["user", "revoked_at"], name="auth_sessions_user_revoked_idx"),
            models.Index(fields=["expires_at"], name="auth_sessions_expires_at_idx"),
            models.Index(fields=["created_at"], name="auth_sessions_created_at_idx"),
        ]

    @property
    def is_active_session(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()

    def revoke(self) -> None:
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at", "updated_at"])

    def __str__(self) -> str:
        return f"{self.user.email} | {self.created_at}"
