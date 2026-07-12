from uuid import UUID

from rest_framework import status
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.access_service.models import PolicyScope
from apps.access_service.services.permission_service import AccessDeniedError, check_permission, get_effective_scope
from apps.business_service.mock_data import create_object, delete_object, get_object, list_objects, update_object
from apps.business_service.serializers import OrderSerializer, ProductSerializer, StoreSerializer


class BusinessCollectionView(APIView):
    permission_classes = [IsAuthenticated]
    resource_code = ""
    serializer_class = None
    has_owner = False

    def get(self, request) -> Response:
        scope = get_effective_scope(user=request.user, resource_code=self.resource_code, action_code="read")
        if scope == PolicyScope.NONE:
            raise PermissionDenied("You do not have permission to read this resource.")
        objects = list_objects(self.resource_code)
        if self.has_owner and scope == PolicyScope.OWN:
            objects = [value for value in objects if str(value["owner_id"]) == str(request.user.id)]
        elif scope != PolicyScope.ALL:
            raise PermissionDenied("You do not have permission to read this resource.")
        return Response(self.serializer_class(objects, many=True).data)

    def post(self, request) -> Response:
        owner_id = request.user.id if self.has_owner else None
        try:
            check_permission(
                user=request.user, resource_code=self.resource_code,
                action_code="create", object_owner_id=owner_id,
            )
        except AccessDeniedError as error:
            raise PermissionDenied(str(error)) from error
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data.copy()
        if self.has_owner:
            data["owner_id"] = request.user.id
        value = create_object(self.resource_code, data)
        return Response(self.serializer_class(value).data, status=status.HTTP_201_CREATED)


class BusinessDetailView(APIView):
    permission_classes = [IsAuthenticated]
    resource_code = ""
    serializer_class = None
    has_owner = False

    def _get(self, object_id: UUID) -> dict:
        value = get_object(self.resource_code, object_id)
        if value is None:
            raise NotFound("Object not found.")
        return value

    def _require(self, request, action: str, value: dict) -> None:
        owner_id = value.get("owner_id") if self.has_owner else None
        try:
            check_permission(
                user=request.user, resource_code=self.resource_code,
                action_code=action, object_owner_id=owner_id,
            )
        except AccessDeniedError as error:
            raise PermissionDenied(str(error)) from error

    def get(self, request, object_id: UUID) -> Response:
        value = self._get(object_id)
        self._require(request, "read", value)
        return Response(self.serializer_class(value).data)

    def patch(self, request, object_id: UUID) -> Response:
        value = self._get(object_id)
        self._require(request, "update", value)
        if self.has_owner and "owner_id" in request.data:
            raise ValidationError({"owner_id": ["The order owner cannot be changed."]})
        serializer = self.serializer_class(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated = update_object(self.resource_code, object_id, serializer.validated_data)
        return Response(self.serializer_class(updated).data)

    def delete(self, request, object_id: UUID) -> Response:
        value = self._get(object_id)
        self._require(request, "delete", value)
        delete_object(self.resource_code, object_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrderListView(BusinessCollectionView):
    resource_code = "orders"
    serializer_class = OrderSerializer
    has_owner = True


class OrderDetailView(BusinessDetailView):
    resource_code = "orders"
    serializer_class = OrderSerializer
    has_owner = True


class ProductListView(BusinessCollectionView):
    resource_code = "products"
    serializer_class = ProductSerializer


class ProductDetailView(BusinessDetailView):
    resource_code = "products"
    serializer_class = ProductSerializer


class StoreListView(BusinessCollectionView):
    resource_code = "stores"
    serializer_class = StoreSerializer


class StoreDetailView(BusinessDetailView):
    resource_code = "stores"
    serializer_class = StoreSerializer
