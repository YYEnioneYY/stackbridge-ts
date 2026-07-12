from rest_framework import serializers


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
        max_length=255,
    )

    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128,
        trim_whitespace=False,
    )

    password_repeat = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128,
        trim_whitespace=False,
    )

    first_name = serializers.CharField(
        required=True,
        max_length=100,
        allow_blank=False,
    )

    last_name = serializers.CharField(
        required=True,
        max_length=100,
        allow_blank=False,
    )

    middle_name = serializers.CharField(
        required=False,
        max_length=100,
        allow_blank=True,
        default="",
    )

    def validate_email(self, value: str) -> str:
        return value.strip().lower()

    def validate(self, attrs):
        if attrs["password"] != attrs["password_repeat"]:
            raise serializers.ValidationError(
                {
                    "password_repeat": (
                        "Passwords do not match."
                    )
                }
            )

        return attrs