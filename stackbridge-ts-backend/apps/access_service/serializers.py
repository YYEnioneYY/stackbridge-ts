from rest_framework import serializers

from apps.access_service.models import AccessAction, AccessPolicy, AccessResource, PolicyScope, Role, UserRoleAssignment


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("id", "code", "name", "description", "is_system", "is_active", "created_at", "updated_at")
        read_only_fields = ("id", "is_system", "is_active", "created_at", "updated_at")
        extra_kwargs = {"code": {"validators": []}}


class RoleInputSerializer(serializers.Serializer):
    code = serializers.RegexField(r"^[a-z][a-z0-9_]*$", max_length=50, required=False)
    name = serializers.CharField(max_length=100, required=False, allow_blank=False)
    description = serializers.CharField(required=False, allow_blank=True, default="")


class RoleAssignmentSerializer(serializers.ModelSerializer):
    role_code = serializers.CharField(source="role.code", read_only=True)

    class Meta:
        model = UserRoleAssignment
        fields = ("id", "user_id", "role_id", "role_code", "assigned_by_id", "revoked_by_id", "revoked_at", "created_at")


class RoleAssignmentInputSerializer(serializers.Serializer):
    role_id = serializers.UUIDField()


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessResource
        fields = ("id", "code", "name", "description", "has_owner", "is_active", "created_at", "updated_at")
        read_only_fields = ("id", "is_active", "created_at", "updated_at")
        extra_kwargs = {"code": {"validators": []}}


class ResourceInputSerializer(serializers.Serializer):
    code = serializers.RegexField(r"^[a-z][a-z0-9_]*$", max_length=100, required=False)
    name = serializers.CharField(max_length=100, required=False, allow_blank=False)
    description = serializers.CharField(required=False, allow_blank=True, default="")
    has_owner = serializers.BooleanField(required=False, default=False)


class ActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessAction
        fields = ("id", "code", "name", "description", "is_active", "created_at", "updated_at")
        read_only_fields = ("id", "is_active", "created_at", "updated_at")
        extra_kwargs = {"code": {"validators": []}}


class ActionInputSerializer(serializers.Serializer):
    code = serializers.RegexField(r"^[a-z][a-z0-9_]*$", max_length=50, required=False)
    name = serializers.CharField(max_length=100, required=False, allow_blank=False)
    description = serializers.CharField(required=False, allow_blank=True, default="")


class PolicySerializer(serializers.ModelSerializer):
    role_code = serializers.CharField(source="role.code", read_only=True)
    resource_code = serializers.CharField(source="resource.code", read_only=True)
    action_code = serializers.CharField(source="action.code", read_only=True)

    class Meta:
        model = AccessPolicy
        fields = (
            "id", "role_id", "role_code", "resource_id", "resource_code", "action_id", "action_code",
            "scope", "is_active", "created_at", "updated_at",
        )


class PolicyInputSerializer(serializers.Serializer):
    role_id = serializers.UUIDField(required=False)
    resource_id = serializers.UUIDField(required=False)
    action_id = serializers.UUIDField(required=False)
    scope = serializers.ChoiceField(choices=PolicyScope.values, required=False)
    is_active = serializers.BooleanField(required=False, default=True)
