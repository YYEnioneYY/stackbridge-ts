from copy import deepcopy
from threading import RLock
from uuid import UUID, uuid4


_lock = RLock()
_orders: dict[UUID, dict] = {}
_products: dict[UUID, dict] = {
    UUID("00000000-0000-0000-0000-000000000101"): {
        "id": UUID("00000000-0000-0000-0000-000000000101"), "name": "Demo product", "price": "99.90",
    }
}
_stores: dict[UUID, dict] = {
    UUID("00000000-0000-0000-0000-000000000201"): {
        "id": UUID("00000000-0000-0000-0000-000000000201"), "name": "Demo store", "city": "Moscow",
    }
}


def collection(resource: str) -> dict[UUID, dict]:
    return {"orders": _orders, "products": _products, "stores": _stores}[resource]


def list_objects(resource: str) -> list[dict]:
    with _lock:
        return deepcopy(list(collection(resource).values()))


def get_object(resource: str, object_id: UUID) -> dict | None:
    with _lock:
        value = collection(resource).get(object_id)
        return deepcopy(value) if value else None


def create_object(resource: str, data: dict) -> dict:
    with _lock:
        object_id = uuid4()
        value = {"id": object_id, **data}
        collection(resource)[object_id] = value
        return deepcopy(value)


def update_object(resource: str, object_id: UUID, data: dict) -> dict | None:
    with _lock:
        value = collection(resource).get(object_id)
        if value is None:
            return None
        value.update(data)
        value["id"] = object_id
        return deepcopy(value)


def delete_object(resource: str, object_id: UUID) -> bool:
    with _lock:
        return collection(resource).pop(object_id, None) is not None
