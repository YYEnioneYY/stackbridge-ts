from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import F, Q
from django.utils import timezone

from apps.common.models import BaseModel


access_code_validator = RegexValidator(
    regex=r"^[a-z][a-z0-9_]*$",
    message=(
        "Code must start with a lowercase Latin letter and contain "
        "only lowercase Latin letters, numbers, and underscores."
    ),
)


class PolicyScope(models.TextChoices):
    NONE = "none", "No access"
    OWN = "own", "Own objects"
    ALL = "all", "All objects"


class Role(BaseModel):
    code = models.CharField(
        max_length=50,
        unique=True,
        validators=[access_code_validator],
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    is_system = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "access_roles"
        indexes = [
            models.Index(
                fields=["is_active"],
                name="access_roles_active_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.code


class UserRoleAssignment(BaseModel):
    user = models.ForeignKey(
        "auth_service.User",
        on_delete=models.CASCADE,
        related_name="role_assignments",
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        related_name="user_assignments",
    )

    assigned_by = models.ForeignKey(
        "auth_service.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_role_assignments",
    )
    revoked_by = models.ForeignKey(
        "auth_service.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="revoked_role_assignments",
    )

    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        db_table = "access_user_role_assignments"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role"],
                condition=Q(revoked_at__isnull=True),
                name="access_user_role_active_uniq",
            ),
            models.CheckConstraint(
                condition=(
                    Q(revoked_at__isnull=True)
                    | Q(revoked_at__gte=F("created_at"))
                ),
                name="access_user_role_revoke_time",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "revoked_at"],
                name="access_ur_user_revoked_idx",
            ),
            models.Index(
                fields=["role", "revoked_at"],
                name="access_ur_role_revoked_idx",
            ),
        ]

    @property
    def is_active_assignment(self) -> bool:
        return self.revoked_at is None

    def revoke(self, revoked_by=None) -> None:
        if self.revoked_at is not None:
            return

        self.revoked_at = timezone.now()
        self.revoked_by = revoked_by

        self.save(
            update_fields=[
                "revoked_at",
                "revoked_by",
                "updated_at",
            ]
        )

    def __str__(self) -> str:
        return f"{self.user.email} -> {self.role.code}"


class AccessResource(BaseModel):
    code = models.CharField(
        max_length=100,
        unique=True,
        validators=[access_code_validator],
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    has_owner = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "access_resources"
        indexes = [
            models.Index(
                fields=["is_active"],
                name="access_res_active_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.code


class AccessAction(BaseModel):
    code = models.CharField(
        max_length=50,
        unique=True,
        validators=[access_code_validator],
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, default="")

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "access_actions"
        indexes = [
            models.Index(
                fields=["is_active"],
                name="access_actions_active_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.code


class AccessPolicy(BaseModel):
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        related_name="access_policies",
    )
    resource = models.ForeignKey(
        AccessResource,
        on_delete=models.PROTECT,
        related_name="access_policies",
    )
    action = models.ForeignKey(
        AccessAction,
        on_delete=models.PROTECT,
        related_name="access_policies",
    )

    scope = models.CharField(
        max_length=10,
        choices=PolicyScope.choices,
        default=PolicyScope.NONE,
    )

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "access_policies"
        constraints = [
            models.UniqueConstraint(
                fields=["role", "resource", "action"],
                name="access_policy_role_res_act_uniq",
            ),
            models.CheckConstraint(
                condition=Q(
                    scope__in=[
                        PolicyScope.NONE,
                        PolicyScope.OWN,
                        PolicyScope.ALL,
                    ]
                ),
                name="access_policy_scope_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=["role", "resource", "action"],
                name="access_policy_lookup_idx",
            ),
            models.Index(
                fields=["resource", "action", "is_active"],
                name="access_policy_res_act_idx",
            ),
        ]

    def clean(self) -> None:
        super().clean()

        if (
            self.scope == PolicyScope.OWN
            and self.resource_id is not None
            and not self.resource.has_owner
        ):
            raise ValidationError(
                {
                    "scope": (
                        "The 'own' scope cannot be used because "
                        "the selected resource does not have an owner."
                    )
                }
            )

    def __str__(self) -> str:
        return (
            f"{self.role.code}:"
            f"{self.resource.code}:"
            f"{self.action.code}:"
            f"{self.scope}"
        )