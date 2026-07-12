from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(write_only=True, min_length=8, max_length=128, trim_whitespace=False)
    password_repeat = serializers.CharField(write_only=True, min_length=8, max_length=128, trim_whitespace=False)
    first_name = serializers.CharField(max_length=100, allow_blank=False)
    last_name = serializers.CharField(max_length=100, allow_blank=False)
    middle_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default="")

    def validate_email(self, value: str) -> str:
        return value.strip().lower()

    def validate(self, attrs: dict) -> dict:
        if attrs["password"] != attrs["password_repeat"]:
            raise serializers.ValidationError({"password_repeat": ["Passwords do not match."]})
        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(write_only=True, max_length=128, trim_whitespace=False)

    def validate_email(self, value: str) -> str:
        return value.strip().lower()


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(trim_whitespace=False)


class TokenPairSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    token_type = serializers.CharField()
    access_expires_at = serializers.DateTimeField()
    refresh_expires_at = serializers.DateTimeField()
