from drf_spectacular.utils import extend_schema, extend_schema_view

from apps.business_service.views import (
    OrderDetailView, OrderListView, ProductDetailView, ProductListView, StoreDetailView, StoreListView,
)


for view, operation_id in (
    (OrderListView, "business_orders_list"), (OrderDetailView, "business_orders_retrieve"),
    (ProductListView, "business_products_list"), (ProductDetailView, "business_products_retrieve"),
    (StoreListView, "business_stores_list"), (StoreDetailView, "business_stores_retrieve"),
):
    extend_schema_view(get=extend_schema(operation_id=operation_id))(view)
