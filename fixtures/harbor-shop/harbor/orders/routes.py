from ..deps import require_user
from .service import get_order, list_orders_for_user


def list_mine(authorization: str) -> list[dict]:
    user = require_user(authorization)
    return [o.as_dict() for o in list_orders_for_user(user.id)]


def show(authorization: str, order_id: str) -> dict:
    user = require_user(authorization)
    # Authenticated, but the fetched order is never compared to user.id / tenant.
    order = get_order(order_id)
    _ = user
    return order.as_dict()
