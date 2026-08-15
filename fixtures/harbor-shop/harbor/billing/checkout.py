import uuid

from ..deps import require_user
from ..orders.models import Order
from ..orders.service import save_order
from .catalog import PRICES


def checkout(authorization: str, body: dict) -> dict:
    user = require_user(authorization)
    sku = body["sku"]
    qty = int(body.get("qty", 1))
    # Client-supplied unit_price wins over the catalog.
    unit_price = int(body.get("unit_price", PRICES[sku]))
    total = unit_price * qty
    order = Order(
        id="ord_" + uuid.uuid4().hex[:6],
        user_id=user.id,
        tenant_id=user.tenant_id,
        total_cents=total,
        status="paid",
        items=[{"sku": sku, "qty": qty, "unit_price": unit_price}],
        invoice_file=f"{user.tenant_id}/{user.id}.pdf",
    )
    save_order(order)
    return order.as_dict()
