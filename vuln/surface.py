"""Source/sink map and extra leads for multi-step exploit hunts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .config import MAX_FILE_BYTES

SOURCE_PATTERNS: list[tuple[str, str]] = [
    (r"request\.(args|form|json|data|files|values|GET|POST|headers|cookies|query)", "http-source"),
    (r"req\.(body|query|params|headers|cookies|file)", "http-source"),
    (r"\bbody\.get\(|payload\.get\(|params\[|searchParams", "http-source"),
    (r"@app\.(get|post|put|patch|delete)|router\.(get|post)", "route-entry"),
    (r"process\.env|os\.environ|getenv\(", "env-source"),
    (r"webhook|callback|sns|sqs|pubsub", "callback-source"),
]

SINK_PATTERNS: list[tuple[str, str]] = [
    (r"execute\(|executemany\(|raw\(|cursor\.|f[\"'].*SELECT|\.query\(", "sql"),
    (r"os\.system|subprocess\.|popen\(|shell=True|child_process|exec\(|eval\(", "exec"),
    (r"render_template|jinja|Mustache|Handlebars|Nunjucks", "ssti"),
    (r"pickle\.|yaml\.load|unserialize|Marshal|ObjectInputStream|JSON\.parse\(.*reviver", "deser"),
    (r"requests\.(get|post|put|request)|httpx\.|urllib|fetch\(|axios\.|got\(", "ssrf"),
    (r"open\(|Path\(|send_file|sendFile|createReadStream|res\.download", "fs"),
    (r"redirect\(|Response\.redirect|window\.location|res\.redirect", "redirect"),
    (r"innerHTML|dangerouslySetInnerHTML|document\.write", "xss"),
    (r"jwt\.|encode_token|decode_token|sign\(|verify\(", "crypto"),
    (r"setattr\(|update\(.*request|mass.?assign", "mass-assign"),
    (r"send_mail|smtp|ses\.|twilio|slack", "notify"),
]

COMPLEX_LEADS: list[tuple[str, str]] = [
    (r"csrf_exempt|@csrf_exempt|csrf\s*=\s*False", "CSRF disabled"),
    (r"CORS\(|cors\(|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*", "CORS star"),
    (r"DEBUG\s*=\s*True|app\.debug\s*=\s*True|Flask\(__name__\)", "debug / flask default"),
    (r"allow_origins\s*=\s*\[?\s*[\"']\*[\"']", "CORS allow all"),
    (r"SameSite\s*=\s*None|samesite\s*=\s*none", "cookie SameSite=None"),
    (r"secure\s*=\s*False|httponly\s*=\s*False", "insecure cookie flags"),
    (r"algorithm\s*=\s*header|algorithms\s*=\s*\[|get\([\"']alg", "JWT alg from attacker"),
    (r"role\s*=\s*(payload|token|claims)|[\"']role[\"']\].*token", "role taken from token"),
    (r"compare_digest|==\s*password|password\s*==", "password compare"),
    (r"SELECT \* FROM users|RETURNING \*|password[,)]", "password field in query"),
    (r"skip_auth|no_auth|public\s*=\s*True|authentication_classes\s*=\s*\[\]", "auth skipped"),
    (r"atomic|select_for_update|FOR UPDATE|transaction", "locking / race"),
    (r"threading|asyncio\.|gevent|multiprocess|race|TOCTOU", "concurrency primitive"),
    (r"graphql|graphene|gql\(|apollo", "GraphQL surface"),
    (r"introspection|__schema|GraphQLPlayground", "GraphQL introspection"),
    (r"oauth|openid|oidc|authorize\?|redirect_uri", "OAuth / OIDC"),
    (r"state\s*=\s*None|state is None|without state", "OAuth missing state"),
    (r"S3|presign|generate_presigned|boto3", "cloud signed URL"),
    (r"169\.254\.169\.254|metadata\.google|instance-data", "cloud metadata SSRF"),
    (r"redirect_uri|next=|returnTo|goto=|continue=", "open redirect param"),
    (r"serialize|unserialize|pickle|Marshal|ObjectInput", "deser sink"),
    (r"prototype|__proto__|constructor\[|merge\(.*req", "prototype pollution"),
    (r"\$where|\$regex|\$gt|\$ne", "NoSQL operator"),
    (r"child_process|execSync|spawn\(", "node command sink"),
    (r"dangerouslySetInnerHTML|v-html=", "stored XSS sink"),
    (r"Feature.?flag|launchdarkly|skip_payment|bypass", "feature-flag bypass"),
    (r"idempotency|replay|nonce", "replay / idempotency"),
    (r"websocket|socket\.io|@sock", "websocket"),
    (r"admin.?only|is_staff|is_superuser|role\s*==\s*[\"']admin", "admin gate"),
    (r"tenant_id|org_id|account_id|workspace_id", "tenancy field"),
]


def _read(workdir: Path, rel: str) -> str:
    target = (workdir / rel).resolve()
    if not str(target).startswith(str(workdir.resolve())) or not target.is_file():
        raise FileNotFoundError(rel)
    data = target.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def extract_surface(workdir: Path, index: dict[str, Any], limit: int = 80) -> dict[str, Any]:
    sources: list[str] = []
    sinks: list[str] = []
    src_rx = [(re.compile(p, re.I), lab) for p, lab in SOURCE_PATTERNS]
    sink_rx = [(re.compile(p, re.I), lab) for p, lab in SINK_PATTERNS]
    for meta in (index.get("files") or [])[:60]:
        rel = meta.get("path") or ""
        try:
            text = _read(workdir, rel)
        except (OSError, ValueError, FileNotFoundError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rx, lab in src_rx:
                if rx.search(line):
                    sources.append(f"{rel}:{i} [{lab}] {line.strip()[:140]}")
                    break
            for rx, lab in sink_rx:
                if rx.search(line):
                    sinks.append(f"{rel}:{i} [{lab}] {line.strip()[:140]}")
                    break
            if len(sources) >= limit and len(sinks) >= limit:
                break
    return {
        "sources": sources[:limit],
        "sinks": sinks[:limit],
        "hint": (
            "Trace attacker-controlled sources into sinks across files. "
            "A source in a route and a sink in a helper with no sanitizer is an exploit."
        ),
    }
