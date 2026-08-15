from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .agents import BUILTIN_AGENTS

_AGENT_RANK = {a["id"]: a.get("rank", 50) for a in BUILTIN_AGENTS}
from .db import dumps, init_db, loads, row_to_dict, tx

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def seed_agents() -> None:
    init_db()
    with tx() as conn:
        existing = {row["id"] for row in conn.execute("SELECT id FROM agents")}
        for agent in BUILTIN_AGENTS:
            if agent["id"] in existing:
                conn.execute(
                    """
                    UPDATE agents
                    SET name=?, role=?, phase=?, description=?, focus=?, builtin=1
                    WHERE id=? AND builtin=1
                    """,
                    (
                        agent["name"],
                        agent["role"],
                        agent["phase"],
                        agent["description"],
                        agent["focus"],
                        agent["id"],
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO agents (id, name, role, phase, description, focus, builtin, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        agent["id"],
                        agent["name"],
                        agent["role"],
                        agent["phase"],
                        agent["description"],
                        agent["focus"],
                        1 if agent["enabled"] else 0,
                    ),
                )


def list_agents() -> list[dict[str, Any]]:
    with tx() as conn:
        rows = conn.execute("SELECT * FROM agents").fetchall()
    out = []
    for row in rows:
        item = row_to_dict(row)
        item["builtin"] = bool(item["builtin"])
        item["enabled"] = bool(item["enabled"])
        out.append(item)
    out.sort(key=lambda a: (_AGENT_RANK.get(a["id"], 55), a["name"]))
    return out


def get_agent(agent_id: str) -> dict[str, Any] | None:
    with tx() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    item = row_to_dict(row)
    if not item:
        return None
    item["builtin"] = bool(item["builtin"])
    item["enabled"] = bool(item["enabled"])
    return item


def upsert_custom_agent(agent: dict[str, Any]) -> dict[str, Any]:
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO agents (id, name, role, phase, description, focus, builtin, enabled)
            VALUES (?, ?, 'specialist', 'specialist', ?, ?, 0, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                focus=excluded.focus,
                enabled=excluded.enabled
            WHERE agents.builtin=0
            """,
            (
                agent["id"],
                agent["name"],
                agent.get("description", ""),
                agent["focus"],
                1 if agent.get("enabled", True) else 0,
            ),
        )
    saved = get_agent(agent["id"])
    if not saved:
        raise RuntimeError("failed to save agent")
    return saved


def set_agent_enabled(agent_id: str, enabled: bool) -> dict[str, Any] | None:
    with tx() as conn:
        conn.execute("UPDATE agents SET enabled=? WHERE id=?", (1 if enabled else 0, agent_id))
    return get_agent(agent_id)


def delete_custom_agent(agent_id: str) -> bool:
    with tx() as conn:
        cur = conn.execute("DELETE FROM agents WHERE id=? AND builtin=0", (agent_id,))
        return cur.rowcount > 0


def insert_audit(audit: dict[str, Any]) -> None:
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO audits (
                id, name, source, source_kind, workdir, mode, status, focus,
                agent_ids, index_json, threat_model, error, created_at, started_at, finished_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit["id"],
                audit["name"],
                audit["source"],
                audit["source_kind"],
                audit["workdir"],
                audit["mode"],
                audit["status"],
                audit.get("focus", ""),
                dumps(audit.get("agent_ids", [])),
                dumps(audit.get("index_json")),
                dumps(audit.get("threat_model")),
                audit.get("error"),
                audit["created_at"],
                audit.get("started_at"),
                audit.get("finished_at"),
            ),
        )


def update_audit(audit_id: str, **fields: Any) -> None:
    if not fields:
        return
    encoded = {}
    for key, value in fields.items():
        if key in {"agent_ids", "index_json", "threat_model"} and not isinstance(value, str):
            encoded[key] = dumps(value)
        else:
            encoded[key] = value
    assignments = ", ".join(f"{k}=?" for k in encoded)
    with tx() as conn:
        conn.execute(
            f"UPDATE audits SET {assignments} WHERE id=?",
            (*encoded.values(), audit_id),
        )


def _hydrate_audit(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    row["agent_ids"] = loads(row.get("agent_ids"), [])
    row["index_json"] = loads(row.get("index_json"))
    row["threat_model"] = loads(row.get("threat_model"))
    return row


def get_audit(audit_id: str) -> dict[str, Any] | None:
    with tx() as conn:
        row = conn.execute("SELECT * FROM audits WHERE id=?", (audit_id,)).fetchone()
    return _hydrate_audit(row_to_dict(row))


def list_audits() -> list[dict[str, Any]]:
    with tx() as conn:
        rows = conn.execute("SELECT * FROM audits ORDER BY created_at DESC").fetchall()
        counts = {
            r["audit_id"]: r["n"]
            for r in conn.execute(
                "SELECT audit_id, COUNT(*) AS n FROM findings GROUP BY audit_id"
            )
        }
    out = []
    for row in rows:
        item = _hydrate_audit(row_to_dict(row))
        if not item:
            continue
        item["finding_count"] = counts.get(item["id"], 0)
        item.pop("index_json", None)
        out.append(item)
    return out


def overview() -> dict[str, Any]:
    audits = list_audits()
    with tx() as conn:
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        finding_total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in sev_rows:
        key = (row["severity"] or "info").lower()
        if key in counts:
            counts[key] = row["n"]
    live = [
        {
            "id": a["id"],
            "name": a["name"],
            "status": a["status"],
            "mode": a["mode"],
            "findings_so_far": a.get("finding_count") or 0,
        }
        for a in audits
        if a["status"] in {"pending", "running"}
    ]
    completed = sum(1 for a in audits if a["status"] == "completed")
    return {
        "project_count": len(audits),
        "scanned_project_count": completed,
        "finding_total": finding_total,
        "scan_in_progress_count": len(live),
        "severity_counts": counts,
        "live": {"scanning": live},
    }


def insert_event(event: dict[str, Any]) -> dict[str, Any]:
    with tx() as conn:
        cur = conn.execute(
            "INSERT INTO events (audit_id, ts, agent, kind, message, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                event["audit_id"],
                event["ts"],
                event.get("agent"),
                event["kind"],
                event["message"],
                dumps(event.get("payload")) if event.get("payload") is not None else None,
            ),
        )
        event = {**event, "id": cur.lastrowid}
    return event


def list_events(audit_id: str, after_id: int = 0) -> list[dict[str, Any]]:
    with tx() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE audit_id=? AND id>? ORDER BY id ASC",
            (audit_id, after_id),
        ).fetchall()
    out = []
    for row in rows:
        item = row_to_dict(row)
        item["payload"] = loads(item.get("payload"))
        out.append(item)
    return out


DETAIL_KEYS = (
    "owasp",
    "attacker",
    "preconditions",
    "affected_routes",
    "blast_radius",
    "why_sast_misses",
    "confidence_rationale",
    "fix_tests",
)


def pack_details(finding: dict[str, Any]) -> dict[str, Any]:
    details = finding.get("details")
    if not isinstance(details, dict):
        details = {}
    for key in DETAIL_KEYS:
        if finding.get(key) not in (None, "", []):
            details[key] = finding[key]
    return details


def insert_finding(finding: dict[str, Any]) -> None:
    details = pack_details(finding)
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO findings (
                id, audit_id, title, severity, category, cwe, summary, description,
                root_cause, impact, remediation, attack_path, evidence, confidence,
                verified, agent, status, chain_id, created_at, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding["id"],
                finding["audit_id"],
                finding["title"],
                finding["severity"],
                finding["category"],
                finding.get("cwe"),
                finding["summary"],
                finding["description"],
                finding["root_cause"],
                finding["impact"],
                finding["remediation"],
                dumps(finding.get("attack_path", [])),
                dumps(finding.get("evidence", [])),
                finding.get("confidence", 0.5),
                1 if finding.get("verified") else 0,
                finding["agent"],
                finding.get("status", "open"),
                finding.get("chain_id"),
                finding.get("created_at") or now(),
                dumps(details) if details else None,
            ),
        )


def list_findings(audit_id: str) -> list[dict[str, Any]]:
    with tx() as conn:
        rows = conn.execute("SELECT * FROM findings WHERE audit_id=?", (audit_id,)).fetchall()
    items = []
    for row in rows:
        item = row_to_dict(row)
        item["attack_path"] = loads(item.get("attack_path"), [])
        item["evidence"] = loads(item.get("evidence"), [])
        item["details"] = loads(item.get("details"), {}) or {}
        item["verified"] = bool(item["verified"])
        items.append(item)
    items.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), -f["confidence"], f["title"]))
    return items


def get_finding(finding_id: str) -> dict[str, Any] | None:
    with tx() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    item = row_to_dict(row)
    if not item:
        return None
    item["attack_path"] = loads(item.get("attack_path"), [])
    item["evidence"] = loads(item.get("evidence"), [])
    item["details"] = loads(item.get("details"), {}) or {}
    item["verified"] = bool(item["verified"])
    return item


def set_finding_status(finding_id: str, status: str) -> dict[str, Any] | None:
    with tx() as conn:
        conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
    return get_finding(finding_id)


def insert_chain(chain: dict[str, Any]) -> None:
    with tx() as conn:
        conn.execute(
            """
            INSERT INTO chains (id, audit_id, title, severity, summary, steps, finding_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chain["id"],
                chain["audit_id"],
                chain["title"],
                chain["severity"],
                chain["summary"],
                dumps(chain.get("steps", [])),
                dumps(chain.get("finding_ids", [])),
            ),
        )


def list_chains(audit_id: str) -> list[dict[str, Any]]:
    with tx() as conn:
        rows = conn.execute("SELECT * FROM chains WHERE audit_id=?", (audit_id,)).fetchall()
    items = []
    for row in rows:
        item = row_to_dict(row)
        item["steps"] = loads(item.get("steps"), [])
        item["finding_ids"] = loads(item.get("finding_ids"), [])
        items.append(item)
    items.sort(key=lambda c: SEVERITY_RANK.get(c["severity"], 9))
    return items
