from django.db import transaction

from apps.profile_service.models import UserProfile


@transaction.atomic
def update_profile(*, profile: UserProfile, **changes: str) -> UserProfile:
    locked_profile = UserProfile.objects.select_for_update().get(pk=profile.pk)
    for field in ("first_name", "last_name", "middle_name"):
        if field in changes:
            setattr(locked_profile, field, changes[field].strip())
    locked_profile.full_clean()
    locked_profile.save()
    return locked_profile
