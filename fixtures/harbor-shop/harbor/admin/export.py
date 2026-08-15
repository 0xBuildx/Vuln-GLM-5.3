from ..orders.models import ORDERS
from ..users.models import USERS


def export_customers(authorization: str | None = None) -> list[dict]:
    # require_admin exists in deps but is never called.
    _ = authorization
    rows = []
    for user in USERS.values():
        rows.append(
            {
                "id": user.id,
                "email": user.email,
                "password": user.password,
                "role": user.role,
                "orders": [o.id for o in ORDERS.values() if o.user_id == user.id],
            }
        )
    return rows
