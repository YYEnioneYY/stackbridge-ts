from django.db import transaction

from apps.auth_service.models import User
from apps.auth_service.services.session_service import revoke_all_sessions


@transaction.atomic
def soft_delete_account(*, user: User) -> None:
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    locked_user.soft_delete()
    revoke_all_sessions(user=locked_user)
