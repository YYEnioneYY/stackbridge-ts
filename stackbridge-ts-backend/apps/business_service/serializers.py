from rest_framework import serializers


class OrderSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    title = serializers.CharField(max_length=200)
    owner_id = serializers.UUIDField(read_only=True)
    status = serializers.ChoiceField(choices=("new", "processing", "completed", "cancelled"), default="new")


class ProductSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(max_length=200)
    price = serializers.DecimalField(max_digits=12, decimal_places=2)


class StoreSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(max_length=200)
    city = serializers.CharField(max_length=100)
