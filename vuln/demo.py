from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from .ingest import locate

DEMO_THREAT_MODEL = {
    "summary": (
        "Harbor Shop is a multi-tenant storefront. Customers authenticate with JWT, "
        "browse their orders, check out, and download invoices. An admin export and a "
        "Stripe webhook sit beside the customer API. Trust is supposed to be "
        "caller + tenant; several service helpers only key on object id."
    ),
    "services": [
        {"name": "auth", "path": "harbor/auth", "trust": "issues tokens; secret is in-repo"},
        {"name": "orders", "path": "harbor/orders", "trust": "object reads should be owner-scoped"},
        {"name": "billing", "path": "harbor/billing", "trust": "prices must come from catalog"},
        {"name": "admin", "path": "harbor/admin", "trust": "admin role required"},
        {"name": "media", "path": "harbor/media", "trust": "invoice files must stay in tenant dir"},
    ],
    "entry_points": [
        "POST /login",
        "GET /orders/{id}",
        "POST /checkout",
        "POST /webhooks/stripe",
        "GET /admin/export",
        "GET /invoices/{id}",
        "GET /search",
        "PATCH /me",
    ],
    "auth": {
        "mechanism": "HS256 JWT in Authorization: Bearer",
        "helpers": ["get_current_user", "require_user", "require_admin"],
        "gaps": [
            "decode_token accepts alg=none",
            "require_admin is unused on the export route",
            "order fetch is authenticated but not authorized",
        ],
    },
    "sensitive_objects": ["Order", "User.password", "invoice files", "catalog prices"],
    "trust_boundaries": [
        "customer → API",
        "tenant north ↔ tenant south",
        "Stripe webhook → order status",
        "filename → filesystem",
    ],
    "hunt_leads": [
        "get_order(order_id) has no owner predicate",
        "checkout reads unit_price from the body",
        "export_customers never calls require_admin",
        "download joins UPLOAD_ROOT with a caller-supplied filename",
    ],
}

DEMO_TEMPLATES: list[dict[str, Any]] = [
    {
        "id_suffix": "idor-order",
        "title": "Any authenticated shopper can read any order by id",
        "severity": "critical",
        "category": "idor",
        "cwe": "CWE-639",
        "agent": "idor",
        "summary": (
            "GET /orders/{id} requires a login but then loads the order by primary key. "
            "The current user is never compared to order.user_id or tenant_id."
        ),
        "description": (
            "A classic cross-file BOLA. The route in orders/routes.py authenticates the "
            "caller, then hands a client-supplied id to orders/service.py:get_order, which "
            "returns whatever row exists. Ada can fetch Ben's paid desk order (ord_201) "
            "and the invoice path that comes with it."
        ),
        "root_cause": (
            "Authorization was implemented as 'is logged in' at the edge and never as "
            "'owns this object' in the data layer."
        ),
        "impact": "Cross-tenant order, address, and invoice disclosure. Stepping stone to file read.",
        "remediation": (
            "Change get_order to require caller.id / caller.tenant_id in the lookup. "
            "Fail closed. Add a regression test: user A requesting user B's id returns 404."
        ),
        "attack_path": [
            "Log in as any customer and obtain a JWT.",
            "GET /orders/ord_201 (or enumerate ord_*).",
            "Read another tenant's items, totals, and invoice_file.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/orders/routes.py",
                "contains": "order = get_order(order_id)",
                "why": "Authenticated handler forwards the raw id and discards the user.",
            },
            {
                "path": "harbor/orders/service.py",
                "contains": "Looks up by primary key only",
                "why": "Data layer has no owner or tenant predicate.",
            },
        ],
        "confidence": 0.96,
    },
    {
        "id_suffix": "admin-export",
        "title": "Customer export is reachable without an admin role",
        "severity": "critical",
        "category": "broken_access",
        "cwe": "CWE-862",
        "agent": "access",
        "summary": (
            "GET /admin/export returns every user, including plaintext passwords. "
            "require_admin exists in deps.py and is never called."
        ),
        "description": (
            "The helper that would enforce the admin role is defined and unused. The "
            "export handler accepts an Authorization header only to ignore it, then "
            "serializes the in-memory user table."
        ),
        "root_cause": "Authorization helper exists but is not wired to the sensitive route.",
        "impact": "Full customer dump, including reusable passwords and role map.",
        "remediation": "Call require_admin(authorization) before building the export. Stop returning password hashes (or plaintext).",
        "attack_path": [
            "Call GET /admin/export with no token, or any customer token.",
            "Receive emails, passwords, roles, and order ids.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/admin/export.py",
                "contains": "require_admin exists in deps but is never called",
                "why": "Handler documents that the admin check is skipped.",
            },
            {
                "path": "harbor/deps.py",
                "contains": "def require_admin",
                "why": "The intended control lives one module away and is unused.",
            },
        ],
        "confidence": 0.95,
    },
    {
        "id_suffix": "price-tamper",
        "title": "Checkout trusts client-supplied unit_price",
        "severity": "high",
        "category": "business_logic",
        "cwe": "CWE-472",
        "agent": "logic",
        "summary": "A shopper can buy a desk for 1 cent by sending unit_price in the checkout body.",
        "description": (
            "billing/catalog.py has real prices, but checkout.py prefers body['unit_price'] "
            "over PRICES[sku]. The order is persisted as paid at the attacker-chosen total."
        ),
        "root_cause": "Price is treated as client state instead of server state.",
        "impact": "Arbitrary undercharge. Pairs with the unpaid webhook to mark anything paid.",
        "remediation": "Ignore client prices. Always multiply catalog price by sanitized qty. Recompute totals server-side.",
        "attack_path": [
            "POST /checkout with sku=desk and unit_price=1.",
            "Order is stored as paid at 1 cent.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/billing/checkout.py",
                "contains": "Client-supplied unit_price wins over the catalog",
                "why": "Attacker-controlled price is written onto the order.",
            },
            {
                "path": "harbor/billing/catalog.py",
                "contains": '"desk": 150000',
                "why": "A real catalog exists and is not authoritative.",
            },
        ],
        "confidence": 0.94,
    },
    {
        "id_suffix": "mass-assign",
        "title": "Profile update mass-assigns role and tenant",
        "severity": "critical",
        "category": "broken_access",
        "cwe": "CWE-915",
        "agent": "access",
        "summary": "PATCH /me copies every body key onto the User, including role and tenant_id.",
        "description": (
            "update_profile loops hasattr and setattr. A customer can become admin or jump "
            "tenants, which then unlocks admin-only data even if export is later fixed."
        ),
        "root_cause": "Unfiltered mass assignment on a privileged field.",
        "impact": "Self-service privilege escalation and tenant escape.",
        "remediation": "Allowlist display_name only. Role and tenant changes must go through an admin-only service.",
        "attack_path": [
            "PATCH /me with {\"role\":\"admin\"}.",
            "Call any admin surface as the newly minted admin.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/users/routes.py",
                "contains": "Mass assignment: callers can set role",
                "why": "Loop writes attacker keys onto the user model.",
            }
        ],
        "confidence": 0.93,
    },
    {
        "id_suffix": "jwt-none",
        "title": "JWT decoder accepts alg=none and a hardcoded secret",
        "severity": "critical",
        "category": "auth",
        "cwe": "CWE-347",
        "agent": "auth",
        "summary": "Forged tokens with alg=none are trusted. The HS256 secret is committed in config.py.",
        "description": (
            "decode_token returns the payload whenever the header says alg=none, skipping "
            "the HMAC. Combined with a hardcoded JWT_SECRET, anyone can mint admin tokens."
        ),
        "root_cause": "Algorithm is taken from the attacker-controlled header; secret is in source.",
        "impact": "Full account takeover for any sub, including u_99 (admin).",
        "remediation": (
            "Allow only HS256/RS256 from a server-side config. Reject alg=none. Load the "
            "secret from the environment. Bind role from the database, not the token."
        ),
        "attack_path": [
            "Craft a JWT header {\"alg\":\"none\"} with payload {\"sub\":\"u_99\",\"role\":\"admin\"}.",
            "Call any authenticated route as the shop owner.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/auth/jwt_util.py",
                "contains": "Accepts alg=none",
                "why": "Forged unsigned tokens are trusted.",
            },
            {
                "path": "harbor/config.py",
                "contains": "harbor-super-secret-please-dont-ship",
                "why": "Signing key is in the repository.",
            },
        ],
        "confidence": 0.97,
    },
    {
        "id_suffix": "path-traversal",
        "title": "Invoice download joins a user-controlled filename",
        "severity": "high",
        "category": "path_traversal",
        "cwe": "CWE-22",
        "agent": "files",
        "summary": (
            "download_invoice takes an optional filename and does Path(UPLOAD_ROOT) / name "
            "with no canonicalization. Combined with the order IDOR, any file the process "
            "can read is reachable."
        ),
        "description": (
            "The order id selects a record (already unscoped). The filename query param "
            "overrides invoice_file. ../../etc/passwd-style segments are not stripped."
        ),
        "root_cause": "Untrusted path segment concatenated onto a trusted root.",
        "impact": "Arbitrary file read as the app user, including other tenants' invoices.",
        "remediation": "Ignore client filenames. Resolve the stored invoice_file, then assert it stays under UPLOAD_ROOT.",
        "attack_path": [
            "Use the order IDOR to learn a valid order id.",
            "GET /invoices/ord_100?filename=../../etc/passwd.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/media/download.py",
                "contains": "User-controlled filename joined onto the invoice root",
                "why": "Caller-supplied name is joined with no sandbox check.",
            }
        ],
        "confidence": 0.91,
    },
    {
        "id_suffix": "sqli-search",
        "title": "Order search concatenates the query into SQL",
        "severity": "high",
        "category": "injection",
        "cwe": "CWE-89",
        "agent": "injection",
        "summary": "search_orders builds LIKE '%{q}%' with an f-string and never applies the caller’s tenant.",
        "description": (
            "The user is required but unused. q comes from the query string and is spliced "
            "into SQL. This is both injection and a data leak."
        ),
        "root_cause": "String-built SQL plus unused authz context.",
        "impact": "Read or modify the orders table; dump other tenants.",
        "remediation": "Use a parameterized LIKE. Filter WHERE user_id = ? or tenant_id = ?.",
        "attack_path": [
            "GET /search?q=x%' OR 1=1 --",
            "Receive every order row.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/search.py",
                "contains": "q is interpolated",
                "why": "Attacker string is concatenated into the statement.",
            }
        ],
        "confidence": 0.92,
    },
    {
        "id_suffix": "webhook-replay",
        "title": "Stripe webhook has no signature check and overwrites status",
        "severity": "high",
        "category": "business_logic",
        "cwe": "CWE-345",
        "agent": "logic",
        "summary": "Anyone who can POST /webhooks/stripe can mark any order paid or refunded.",
        "description": (
            "The handler trusts payload.order_id and payload.status. There is no Stripe "
            "signature header, timestamp, or shared secret. Combined with get_order's "
            "unscoped lookup, this is a free status oracle."
        ),
        "root_cause": "Unauthenticated state-changing callback.",
        "impact": "Mark unpaid orders paid, or flip paid orders to refunded.",
        "remediation": "Verify Stripe-Signature against the endpoint secret. Map event types explicitly. Load the order by the id Stripe signed.",
        "attack_path": [
            "POST /webhooks/stripe {\"order_id\":\"ord_100\",\"status\":\"refunded\"}.",
            "Order status changes with no payment event.",
        ],
        "evidence_locators": [
            {
                "path": "harbor/billing/webhooks.py",
                "contains": "No signature verification",
                "why": "Replayable, unauthenticated status overwrite.",
            }
        ],
        "confidence": 0.9,
    },
]

DEMO_CHAINS = [
    {
        "id_suffix": "takeover-export",
        "title": "Unsigned JWT → admin export of every customer password",
        "severity": "critical",
        "summary": (
            "Forge alg=none as u_99, or skip auth entirely — the export route does not "
            "check a role. One request dumps the user table."
        ),
        "steps": [
            "Mint a none-algorithm token for sub=u_99 (jwt-none).",
            "Or call GET /admin/export with no token (admin-export).",
            "Recover plaintext passwords and pivot into other accounts.",
        ],
        "finding_suffixes": ["jwt-none", "admin-export"],
    },
    {
        "id_suffix": "idor-to-files",
        "title": "Order IDOR chained into invoice path traversal",
        "severity": "critical",
        "summary": (
            "The unscoped order fetch reveals invoice_file names. The download handler "
            "then joins an attacker filename onto UPLOAD_ROOT."
        ),
        "steps": [
            "GET /orders/ord_201 as any user to confirm object access.",
            "GET /invoices/ord_201?filename=../../.env (or another tenant's invoice).",
            "Read secrets or other customers' invoices.",
        ],
        "finding_suffixes": ["idor-order", "path-traversal"],
    },
    {
        "id_suffix": "free-desk",
        "title": "Price tamper plus unsigned webhook = free paid inventory",
        "severity": "high",
        "summary": "Set unit_price=1 at checkout, then force status=paid through the webhook if anything in the flow ever stops being automatic.",
        "steps": [
            "POST /checkout sku=desk unit_price=1.",
            "If status is not already paid, POST /webhooks/stripe to force it.",
        ],
        "finding_suffixes": ["price-tamper", "webhook-replay"],
    },
]

DEMO_EVENTS = [
    ("mapper", "think", "Walking Harbor Shop: auth, orders, billing, admin, media."),
    ("mapper", "read", "Indexed 18 source files. JWT + in-memory tables, no ORM scopes."),
    ("mapper", "note", "Trust boundary: customer JWT → object id. Checking whether helpers close it."),
    ("access", "think", "require_admin exists. Searching for call sites."),
    ("access", "read", "harbor/admin/export.py never calls it. Exporting passwords."),
    ("access", "finding", "Admin export is unauthenticated. Mass assignment on /me sets role."),
    ("idor", "think", "Tracing GET /orders/{id} through the service layer."),
    ("idor", "read", "routes.show() authenticates; service.get_order() keys only on id."),
    ("idor", "finding", "Cross-tenant order read. Ada can fetch ord_201."),
    ("logic", "think", "Checkout should take price from catalog, not the body."),
    ("logic", "read", "unit_price = int(body.get('unit_price', PRICES[sku]))."),
    ("logic", "finding", "Client price wins. Webhook has no Stripe signature."),
    ("auth", "read", "decode_token short-circuits when alg is none. Secret is in config.py."),
    ("auth", "finding", "Unsigned admin tokens are trusted."),
    ("files", "read", "download_invoice joins UPLOAD_ROOT with a caller filename."),
    ("files", "finding", "Path traversal on invoices, reachable after the IDOR."),
    ("injection", "read", "search.py interpolates q into LIKE. user is unused."),
    ("injection", "finding", "Authenticated SQLi plus missing tenant filter."),
    ("chain", "think", "Joining IDOR → file read, and JWT none → export."),
    ("verifier", "think", "Checking each cite against source. All eight hold."),
    ("verifier", "note", "Dropped nothing. Evidence locators resolved in-tree."),
]


def materialize_findings(workdir: Path, audit_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for tmpl in DEMO_TEMPLATES:
        evidence = []
        for loc in tmpl["evidence_locators"]:
            found = locate(workdir, loc["path"], loc["contains"])
            if found:
                found["why"] = loc["why"]
                evidence.append(found)
            else:
                evidence.append(
                    {
                        "path": loc["path"],
                        "start_line": 1,
                        "end_line": 1,
                        "snippet": loc["contains"],
                        "why": loc["why"],
                    }
                )
        findings.append(
            {
                "id": f"{audit_id}-{tmpl['id_suffix']}",
                "audit_id": audit_id,
                "title": tmpl["title"],
                "severity": tmpl["severity"],
                "category": tmpl["category"],
                "cwe": tmpl["cwe"],
                "summary": tmpl["summary"],
                "description": tmpl["description"],
                "root_cause": tmpl["root_cause"],
                "impact": tmpl["impact"],
                "remediation": tmpl["remediation"],
                "attack_path": tmpl["attack_path"],
                "evidence": evidence,
                "confidence": tmpl["confidence"],
                "verified": True,
                "agent": tmpl["agent"],
                "status": "open",
                "chain_id": None,
                "details": tmpl.get("details")
                or {
                    "owasp": {
                        "idor": "A01:2021 Broken Access Control",
                        "broken_access": "A01:2021 Broken Access Control",
                        "auth": "A07:2021 Identification and Authentication Failures",
                        "business_logic": "A04:2021 Insecure Design",
                        "injection": "A03:2021 Injection",
                        "path_traversal": "A01:2021 Broken Access Control",
                    }.get(tmpl["category"], "A04:2021 Insecure Design"),
                    "attacker": "any authenticated customer"
                    if tmpl["category"] != "auth"
                    else "unauthenticated (forged token)",
                    "preconditions": tmpl["attack_path"][:1],
                    "affected_routes": [],
                    "blast_radius": tmpl["impact"],
                    "why_sast_misses": "The bug is a missing check across two files, not a tainted sink pattern.",
                    "confidence_rationale": f"Cited source in-tree; confidence {tmpl['confidence']}.",
                    "fix_tests": ["Regression: attacker role requesting victim object id returns 404."],
                },
            }
        )
    return findings


def materialize_chains(audit_id: str) -> list[dict[str, Any]]:
    chains = []
    for tmpl in DEMO_CHAINS:
        chains.append(
            {
                "id": f"{audit_id}-{tmpl['id_suffix']}",
                "audit_id": audit_id,
                "title": tmpl["title"],
                "severity": tmpl["severity"],
                "summary": tmpl["summary"],
                "steps": tmpl["steps"],
                "finding_ids": [f"{audit_id}-{s}" for s in tmpl["finding_suffixes"]],
            }
        )
    return chains


async def play_demo_events(emit, delay: float = 0.18) -> None:
    for agent, kind, message in DEMO_EVENTS:
        await emit(agent=agent, kind=kind, message=message)
        if delay:
            await asyncio.sleep(delay)
