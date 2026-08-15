"""Tiny in-process HTTP-ish router so the surface is obvious to agents."""

from .admin.export import export_customers
from .auth.routes import login
from .billing.checkout import checkout
from .billing.webhooks import stripe_webhook
from .media.download import download_invoice
from .orders.routes import list_mine, show
from .search import search_orders
from .users.routes import get_profile, update_profile


ROUTES = {
    ("POST", "/login"): login,
    ("GET", "/me"): get_profile,
    ("PATCH", "/me"): update_profile,
    ("GET", "/orders"): list_mine,
    ("GET", "/orders/{id}"): show,
    ("POST", "/checkout"): checkout,
    ("POST", "/webhooks/stripe"): stripe_webhook,
    ("GET", "/admin/export"): export_customers,
    ("GET", "/invoices/{id}"): download_invoice,
    ("GET", "/search"): search_orders,
}


def dispatch(method: str, path: str, **kwargs):
    handler = ROUTES[(method, path)]
    return handler(**kwargs)
