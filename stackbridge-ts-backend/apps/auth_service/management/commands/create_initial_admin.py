from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from apps.access_service.models import Role
from apps.access_service.services.role_assignment_service import assign_role
from apps.auth_service.models import User
from apps.auth_service.services.password_service import hash_password
from apps.profile_service.models import UserProfile


class Command(BaseCommand):
    help = "Creates the initial administrator using the custom identity model."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--email", required=True)
        parser.add_argument("--password", required=True)
        parser.add_argument("--first-name", required=True)
        parser.add_argument("--last-name", required=True)
        parser.add_argument("--middle-name", default="")

    @transaction.atomic
    def handle(self, *args, **options) -> None:
        admin_role = Role.objects.select_for_update().filter(code="admin", is_active=True).first()
        if admin_role is None:
            raise CommandError("Active admin role does not exist. Run seed_access_control first.")
        email = options["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise CommandError("A user with this email already exists.")
        try:
            user = User.objects.create(email=email, password_hash=hash_password(options["password"]))
            UserProfile.objects.create(
                user=user,
                first_name=options["first_name"].strip(),
                last_name=options["last_name"].strip(),
                middle_name=options["middle_name"].strip(),
            )
            assign_role(user=user, role=admin_role)
        except IntegrityError as error:
            raise CommandError("The initial administrator could not be created.") from error
        self.stdout.write(self.style.SUCCESS(f"Initial administrator created: {email}"))
