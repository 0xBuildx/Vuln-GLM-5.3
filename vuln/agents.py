from __future__ import annotations

from typing import Any

BUILTIN_AGENTS: list[dict[str, Any]] = [
    {
        "id": "mapper",
        "name": "Mapper",
        "role": "context",
        "phase": "map",
        "description": "Builds the attack surface, trust boundaries, and a working threat model.",
        "focus": (
            "Map the attack surface an exploit author would use. For EVERY entry point produce "
            "a route_table row: method, path, file, handler, auth_observed (what the code actually "
            "checks), auth_expected (what the object/role requires), objects touched, and risk. "
            "Name dead helpers (defined, unused). List static leads that look exploitable. "
            "Do not skip webhooks, admin, files, search, or background jobs. "
            "Do not report full findings yet — but do not hide a missing check in the route_table."
        ),
        "rank": 0,
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "access",
        "name": "Access control",
        "role": "specialist",
        "phase": "specialist",
        "rank": 10,
        "description": "Broken authorization, missing guards, privilege escalation, role confusion.",
        "focus": (
            "Own authorization, not object IDs. For each privileged or mutating route: does the "
            "handler call the real guard (require_admin / role / permission), or is the helper "
            "dead code two files away? Mass assignment of role/tenant, default-allow middleware, "
            "UI-only checks, and unauthenticated admin/export/debug routes are in scope. "
            "Trace the call. A missing decorator is a finding. Do not stop at one bug."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "idor",
        "name": "IDOR / BOLA",
        "role": "specialist",
        "phase": "specialist",
        "rank": 20,
        "description": "Object-level access without ownership or tenant checks.",
        "focus": (
            "Own object-level access. For every handler that takes an id (order, invoice, user, "
            "file, message, tenant): follow it into the service/ORM. If the lookup is by primary "
            "key and the caller is never compared, that is a finding — even if the route is "
            "'authenticated'. Grep get_by_id / filter(id=) / USERS.get / ORDERS.get. "
            "List each object type you reviewed. Missing tenant predicates count."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "logic",
        "name": "Business logic",
        "role": "specialist",
        "phase": "specialist",
        "rank": 30,
        "description": "Workflow skips, payment/quantity tampering, racey state machines.",
        "focus": (
            "Own money, state machines, and callbacks. Checkout must take price from a server "
            "catalog, not the body. Qty/coupon/discount from the client is a finding. Webhooks "
            "need a verified signature. Status must not jump paid/refunded from an untrusted "
            "POST. Replay, negative qty, and skipped payment states are in scope. "
            "Read billing, checkout, payments, orders. Do not leave a webhook unreviewed."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "auth",
        "name": "Auth & sessions",
        "role": "specialist",
        "phase": "specialist",
        "rank": 40,
        "description": "JWT pitfalls, session fixation, hardcoded secrets, weak reset flows.",
        "focus": (
            "Own the token and login path. Read the JWT/session helper in full. alg=none, "
            "algorithm from the header, hardcoded secrets, missing exp, role taken from the "
            "token instead of the DB, plaintext password compare, and reset tokens in URLs "
            "are findings. Skip 'use HTTPS' sermons. Cite the decode/encode function."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "injection",
        "name": "Injection",
        "role": "specialist",
        "phase": "specialist",
        "rank": 50,
        "description": "SQL/NoSQL/command/SSTI that is actually reachable from an entry point.",
        "focus": (
            "Own injection. Grep execute(, raw(, f\"SELECT, '%' + q, shell=True, os.system, "
            "and template render. Then walk backward to a route/query/body. A sink with a "
            "user-controlled string and no parameterization is a finding even if the user is "
            "logged in. Search endpoints are prime. Do not report unrelated f-strings."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "files",
        "name": "Files, SSRF & uploads",
        "role": "specialist",
        "phase": "specialist",
        "rank": 60,
        "description": "Path traversal, SSRF, unrestricted upload, unsafe deserialization.",
        "focus": (
            "Own files and outbound URL. Path(root) / user_filename without a resolve+prefix "
            "check is a finding. So is requests.get(user_url), open redirect to a token, "
            "pickle/yaml.load, and upload then serve. Read download/upload/media helpers. "
            "Chain with any unscoped object fetch that reveals a stored path."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "crypto",
        "name": "Crypto & secrets",
        "role": "specialist",
        "phase": "specialist",
        "rank": 70,
        "description": "Hardcoded keys, weak JWT, custom crypto, sensitive data in logs.",
        "focus": (
            "Own secrets and crypto. Hardcoded JWT/HMAC/API keys that are not placeholders, "
            "MD5/SHA1 passwords, alg confusion, and verify=False are findings. Returning "
            "password fields in any API response is critical. Ignore .env.example and TODO."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "ssrf",
        "name": "SSRF & callbacks",
        "role": "specialist",
        "phase": "specialist",
        "rank": 62,
        "description": "User-controlled URLs, cloud metadata, webhook SSRF, open redirects.",
        "focus": (
            "Own outbound fetches and redirects. Follow every URL built from request/body/db "
            "into requests/httpx/fetch/urllib. No allowlist + user host is a finding. "
            "Check 169.254.169.254, file://, gopher, and redirect_uri / next= open redirects. "
            "Unsigned webhooks that trigger a server-side GET of attacker URL are critical."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "race",
        "name": "Races & state",
        "role": "specialist",
        "phase": "specialist",
        "rank": 64,
        "description": "TOCTOU, double-spend, missing locks on balances and status.",
        "focus": (
            "Own time-of-check/time-of-use. Read-modify-write on balance, inventory, coupons, "
            "and status without a transaction or lock is a finding. Two checkouts of the last "
            "item, redeem-then-refund, and webhook vs user POST interleaving. Cite the "
            "read and the write in different lines/files."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "deser",
        "name": "Deser & templates",
        "role": "specialist",
        "phase": "specialist",
        "rank": 66,
        "description": "Pickle/YAML/unserialize, SSTI, prototype pollution, XXE.",
        "focus": (
            "Own parsers. pickle.loads, yaml.load without Loader, unserialize, "
            "ObjectInputStream, and template render of user strings are findings if reachable. "
            "JS merge of req.body into Object is prototype pollution. XML without defusedxml "
            "is XXE. Trace to a route or job."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "tenant",
        "name": "Tenancy & confused deputy",
        "role": "specialist",
        "phase": "specialist",
        "rank": 68,
        "description": "Cross-tenant reads/writes, org escape, confused-deputy internals.",
        "focus": (
            "Own isolation. If tenant_id/org_id exists on a model, every query must filter it. "
            "Internal endpoints that trust X-User-Id or a forwarded host are confused deputies. "
            "Invite/accept, switch-org, and share-link flows often skip the check. "
            "Prove the missing predicate in the data layer, not just the route."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "agentic",
        "name": "Agentic risks",
        "role": "specialist",
        "phase": "specialist",
        "rank": 80,
        "description": "Prompt injection, excessive agency, insecure tool use in AI features.",
        "focus": (
            "Hunt agentic-application risks if the repo has LLM/tool-calling features: unsanitized "
            "retrieval stuffed into system prompts, tools that execute shell/SQL/HTTP without "
            "allowlists, and confused-deputy agents that honor attacker instructions in untrusted "
            "content. If there is no AI surface, return an empty finding list."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "sweeper",
        "name": "Residual sweeper",
        "role": "specialist",
        "phase": "sweep",
        "rank": 85,
        "description": "Second pass over routes and static leads nobody claimed.",
        "focus": (
            "You run after the specialists. Your job is leftovers: routes with no finding, "
            "static leads not cited, webhooks, search, files, JWT helpers, and catalog vs "
            "client price. Confirm each leftover with read_file. File every real miss. "
            "Do not restate a finding that is already in the prior list unless you have a "
            "new object or a new sink."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "conductor",
        "name": "Exploit conductor",
        "role": "join",
        "phase": "hypothesize",
        "rank": 88,
        "description": "Turns coverage gaps into multi-step exploit hypotheses.",
        "focus": (
            "You are an exploit developer, not a reporter. Given findings, uncovered routes, "
            "sources, and sinks, propose up to 8 MULTI-STEP hypotheses the first wave did not "
            "fully prove. Each hypothesis must name the privilege or data it reaches, the files "
            "to read, and the 2–4 step path. Prefer: auth bypass → object access → file/SQLi; "
            "unsigned JWT → admin; IDOR → stored path → traversal; price tamper → webhook. "
            "Do not repeat a finding title already listed."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "chain",
        "name": "Chain synthesizer",
        "role": "join",
        "phase": "join",
        "rank": 90,
        "description": "Combines individually modest issues into privilege-escalation paths.",
        "focus": (
            "Build the worst realistic chains. Every chain must reach data theft, privilege, "
            "or money. Use source→sink edges and findings as steps. Prefer 3–5 step paths "
            "that cross files. If two bugs do not compose, do not force them."
        ),
        "builtin": True,
        "enabled": True,
    },
    {
        "id": "verifier",
        "name": "Adversarial verifier",
        "role": "join",
        "phase": "join",
        "rank": 100,
        "description": "Tries to disprove each finding. Drops anything without code evidence.",
        "focus": (
            "Disprove sloppy findings, do not delete real bugs. KEEP a finding if the cited "
            "file exists and the described missing check is still missing in that function. "
            "Only drop when you can point at the actual guard in the same flow, or the path "
            "does not exist. Never drop because the app is a demo or the bug is 'too obvious'."
        ),
        "builtin": True,
        "enabled": True,
    },
]


def builtin_by_id() -> dict[str, dict[str, Any]]:
    return {a["id"]: a for a in BUILTIN_AGENTS}


def default_enabled_ids() -> list[str]:
    return [a["id"] for a in BUILTIN_AGENTS if a["enabled"]]
