from django.db import models

from apps.common.models import BaseModel


class UserProfile(BaseModel):
    user = models.OneToOneField(
        "auth_service.User",
        on_delete=models.CASCADE,
        related_name="profile",
    )

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    middle_name = models.CharField(
        max_length=100,
        blank=True,
        default="",
    )

    class Meta:
        db_table = "user_profiles"

    @property
    def full_name(self) -> str:
        name_parts = [
            self.last_name,
            self.first_name,
            self.middle_name,
        ]

        return " ".join(part for part in name_parts if part)

    def __str__(self) -> str:
        return self.full_name