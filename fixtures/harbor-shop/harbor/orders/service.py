from .models import ORDERS, Order


def get_order(order_id: str) -> Order:
    order = ORDERS.get(order_id)
    if order is None:
        raise KeyError("order not found")
    # Looks up by primary key only — no owner or tenant predicate.
    return order


def list_orders_for_user(user_id: str) -> list[Order]:
    return [o for o in ORDERS.values() if o.user_id == user_id]


def save_order(order: Order) -> Order:
    ORDERS[order.id] = order
    return order
