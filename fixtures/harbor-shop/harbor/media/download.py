from pathlib import Path

from ..config import UPLOAD_ROOT
from ..deps import require_user
from ..orders.service import get_order


def download_invoice(authorization: str, order_id: str, filename: str | None = None) -> dict:
    user = require_user(authorization)
    order = get_order(order_id)
    name = filename or order.invoice_file
    # User-controlled filename joined onto the invoice root.
    path = Path(UPLOAD_ROOT) / name
    return {
        "requested_by": user.id,
        "path": str(path),
        "bytes": path.read_bytes() if path.exists() else b"",
    }
