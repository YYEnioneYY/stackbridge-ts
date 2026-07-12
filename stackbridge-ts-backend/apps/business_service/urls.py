from django.urls import path

from apps.business_service.views import (
    OrderDetailView, OrderListView, ProductDetailView, ProductListView, StoreDetailView, StoreListView,
)


urlpatterns = [
    path("orders/", OrderListView.as_view(), name="order-list"),
    path("orders/<uuid:object_id>/", OrderDetailView.as_view(), name="order-detail"),
    path("products/", ProductListView.as_view(), name="product-list"),
    path("products/<uuid:object_id>/", ProductDetailView.as_view(), name="product-detail"),
    path("stores/", StoreListView.as_view(), name="store-list"),
    path("stores/<uuid:object_id>/", StoreDetailView.as_view(), name="store-detail"),
]
