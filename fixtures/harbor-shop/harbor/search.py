import sqlite3

from .deps import require_user


def search_orders(authorization: str, q: str) -> list[tuple]:
    user = require_user(authorization)
    conn = sqlite3.connect("harbor.db")
    # q is interpolated. tenant/user are not applied.
    sql = f"SELECT id, user_id, total_cents FROM orders WHERE sku LIKE '%{q}%'"
    rows = conn.execute(sql).fetchall()
    _ = user
    return rows
