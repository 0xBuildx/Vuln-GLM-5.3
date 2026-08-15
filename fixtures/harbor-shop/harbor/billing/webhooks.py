from ..orders.service import get_order, save_order


def stripe_webhook(payload: dict) -> dict:
    # No signature verification. Replay + status overwrite.
    order = get_order(payload["order_id"])
    order.status = payload.get("status", "paid")
    save_order(order)
    return {"ok": True, "order_id": order.id, "status": order.status}
