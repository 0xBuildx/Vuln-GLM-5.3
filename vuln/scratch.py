"""Per-audit scratchpad so agents share claims and route coverage."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .config import DATA_DIR

_lock = threading.Lock()


def scratch_dir(audit_id: str) -> Path:
    path = DATA_DIR / "scratch" / audit_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _path(audit_id: str, name: str) -> Path:
    return scratch_dir(audit_id) / name


def write_json(audit_id: str, name: str, data: Any) -> None:
    target = _path(audit_id, name)
    with _lock:
        target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(audit_id: str, name: str, default: Any = None) -> Any:
    target = _path(audit_id, name)
    if not target.exists():
        return default
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def init_coverage(audit_id: str, routes: list[dict[str, Any]]) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for route in routes:
        key = f"{route.get('method', 'ANY')} {route.get('path')}"
        table[key] = {
            "status": "open",
            "why": "",
            "agent": "",
            "file": route.get("file") or "",
        }
    payload = {"total": len(table), "reviewed": 0, "routes": table}
    write_json(audit_id, "coverage.json", payload)
    return payload


def merge_reviews(audit_id: str, agent: str, reviews: list[dict[str, Any]]) -> dict[str, Any]:
    cov = read_json(audit_id, "coverage.json", {"total": 0, "reviewed": 0, "routes": {}})
    routes = cov.setdefault("routes", {})
    for item in reviews or []:
        if isinstance(item, str):
            key, status, why = item, "clean", ""
        else:
            method = item.get("method") or "ANY"
            path = item.get("path") or item.get("route") or ""
            key = item.get("key") or (f"{method} {path}".strip() if path else "")
            status = (item.get("status") or "clean").lower()
            why = item.get("why") or ""
        if not key:
            continue
        if key not in routes:
            routes[key] = {"status": "open", "why": "", "agent": "", "file": ""}
        if routes[key]["status"] == "finding" and status == "clean":
            continue
        if status not in {"finding", "clean", "open"}:
            status = "clean"
        routes[key]["status"] = status
        routes[key]["why"] = why
        routes[key]["agent"] = agent
    cov["total"] = len(routes)
    cov["reviewed"] = sum(1 for r in routes.values() if r["status"] in {"finding", "clean"})
    write_json(audit_id, "coverage.json", cov)
    return cov


def mark_finding_routes(audit_id: str, agent: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    reviews = []
    for finding in findings:
        blob = " ".join(
            [
                finding.get("title") or "",
                finding.get("summary") or "",
                finding.get("description") or "",
            ]
        )
        for key in read_json(audit_id, "coverage.json", {}).get("routes", {}):
            path = key.split(" ", 1)[-1]
            if path and path in blob:
                reviews.append({"key": key, "status": "finding", "why": finding.get("title") or ""})
    return merge_reviews(audit_id, agent, reviews)


def uncovered_keys(audit_id: str) -> list[dict[str, Any]]:
    cov = read_json(audit_id, "coverage.json", {"routes": {}})
    out = []
    for key, row in (cov.get("routes") or {}).items():
        if row.get("status") == "open":
            parts = key.split(" ", 1)
            out.append(
                {
                    "key": key,
                    "method": parts[0] if parts else "ANY",
                    "path": parts[1] if len(parts) > 1 else key,
                    "file": row.get("file") or "",
                }
            )
    return out


def coverage_summary(audit_id: str) -> dict[str, Any]:
    cov = read_json(audit_id, "coverage.json", {"total": 0, "reviewed": 0, "routes": {}})
    routes = cov.get("routes") or {}
    return {
        "total": cov.get("total") or len(routes),
        "reviewed": sum(1 for r in routes.values() if r.get("status") in {"finding", "clean"}),
        "findings": sum(1 for r in routes.values() if r.get("status") == "finding"),
        "clean": sum(1 for r in routes.values() if r.get("status") == "clean"),
        "open": sum(1 for r in routes.values() if r.get("status") == "open"),
        "routes": routes,
    }


def append_claim(audit_id: str, agent: str, claim: str) -> None:
    target = _path(audit_id, "claims.jsonl")
    line = json.dumps({"agent": agent, "claim": claim}, ensure_ascii=False)
    with _lock:
        with target.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def recent_claims(audit_id: str, limit: int = 40) -> list[dict[str, Any]]:
    target = _path(audit_id, "claims.jsonl")
    if not target.exists():
        return []
    lines = target.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def snapshot_text(audit_id: str) -> str:
    cov = coverage_summary(audit_id)
    claims = recent_claims(audit_id, 24)
    open_routes = [k for k, r in (cov.get("routes") or {}).items() if r.get("status") == "open"]
    lines = [
        f"Coverage {cov['reviewed']}/{cov['total']} routes "
        f"({cov['findings']} with findings, {cov['clean']} clean, {cov['open']} open).",
        "Open routes: " + (", ".join(open_routes[:30]) or "(none)"),
        "Recent claims:",
    ]
    lines.extend(f"- {c.get('agent')}: {c.get('claim')}" for c in claims[-16:])
    return "\n".join(lines)
