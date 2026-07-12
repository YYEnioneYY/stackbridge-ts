from rest_framework import serializers

from apps.profile_service.models import UserProfile


class ProfileUpdateSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, allow_blank=False, required=False)
    last_name = serializers.CharField(max_length=100, allow_blank=False, required=False)
    middle_name = serializers.CharField(max_length=100, allow_blank=True, required=False)


class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(read_only=True)

    class Meta:
        model = UserProfile
        fields = ("first_name", "last_name", "middle_name", "full_name")
