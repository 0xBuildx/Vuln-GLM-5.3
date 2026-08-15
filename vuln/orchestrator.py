from __future__ import annotations

import asyncio
import re
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from .config import (
    FIXTURE_DIR,
    HUNT_CONCURRENCY,
    HUNT_ROUNDS,
    HUNT_WORKERS,
    active_model,
    active_provider,
    live_ready,
)

_HUNT_POOL = ThreadPoolExecutor(max_workers=max(HUNT_CONCURRENCY, HUNT_WORKERS), thread_name_prefix="vuln-hunt")
_HUNT_SEM: asyncio.Semaphore | None = None


def _hunt_sem() -> asyncio.Semaphore:
    global _HUNT_SEM
    if _HUNT_SEM is None:
        _HUNT_SEM = asyncio.Semaphore(HUNT_CONCURRENCY)
    return _HUNT_SEM
from .demo import (
    DEMO_THREAT_MODEL,
    materialize_chains,
    materialize_findings,
    play_demo_events,
)
from .graph import build_graph, git_changed_files
from .ingest import index_repo, pack_attack_surface, read_file, resolve_source, static_leads
from .scratch import (
    append_claim,
    coverage_summary,
    init_coverage,
    mark_finding_routes,
    merge_reviews,
    read_json,
    snapshot_text,
    uncovered_keys,
    write_json,
)
from .surface import extract_surface
from .llm import LLMError, complete_json, hunt
from .store import (
    get_agent,
    get_audit,
    insert_audit,
    insert_chain,
    insert_event,
    insert_finding,
    list_agents,
    now,
    seed_agents,
    update_audit,
)

RUNNING: dict[str, asyncio.Task] = {}
CANCEL = set()

MAPPER_SCHEMA = """
Return JSON via submit_result:
{
  "summary": "string",
  "services": [{"name": "", "path": "", "trust": ""}],
  "entry_points": ["METHOD /path"],
  "route_table": [
    {
      "method": "GET",
      "path": "/orders/{id}",
      "file": "relative.py",
      "auth_observed": "what the code checks",
      "auth_expected": "what it should check",
      "objects": ["Order"],
      "risk": "high|medium|low"
    }
  ],
  "auth": {"mechanism": "", "helpers": [], "gaps": []},
  "sensitive_objects": [],
  "trust_boundaries": [],
  "hunt_leads": ["file:line + why"],
  "priority_files": ["relative/paths"]
}
Every extracted route must appear in route_table. Do not invent files.
"""

FINDINGS_SCHEMA = """
Return JSON via submit_result:
{
  "notes": "what you proved and what you left clean",
  "reviewed_routes": [
    {"method": "GET", "path": "/orders/{id}", "status": "finding|clean", "why": "owner check missing / scoped by user_id"}
  ],
  "findings": [
    {
      "title": "",
      "severity": "critical|high|medium|low|info",
      "category": "idor|broken_access|business_logic|auth|injection|path_traversal|ssrf|crypto|agentic|other",
      "cwe": "CWE-nnn or null",
      "summary": "one paragraph",
      "description": "how it works across files",
      "root_cause": "",
      "impact": "",
      "remediation": "concrete code change",
      "attack_path": ["step", "step"],
      "evidence": [
        {"path": "relative/file", "start_line": 1, "end_line": 8, "snippet": "code", "why": "what this proves"}
      ],
      "confidence": 0.0,
      "owasp": "A01:2021 Broken Access Control",
      "attacker": "unauthenticated | any authenticated user | other tenant | low-priv role",
      "preconditions": ["what must be true to exploit"],
      "affected_routes": ["METHOD /path"],
      "blast_radius": "what data/privilege is reachable and how far",
      "why_sast_misses": "why a pattern scanner would not flag this",
      "confidence_rationale": "why this confidence",
      "fix_tests": ["regression test that would fail today"]
    }
  ]
}
Write like a pentest finding, not a linter hit. description must name functions and files and walk the data flow. attack_path must be concrete (which id, which user, which response).
Cite real paths only.
reviewed_routes is mandatory. Every route you were assigned must appear as finding or clean.
If a source in one file reaches a sink in another with no check, that is a finding — file it even when each line looks harmless alone.
Always fill attack_path with the exploit steps an attacker would actually take.
Read the scratchpad. Do not re-prove a claim already listed unless you have a new sink.
"""

CHAIN_SCHEMA = """
Return JSON:
{
  "chains": [
    {
      "title": "",
      "severity": "critical|high|medium|low",
      "summary": "",
      "steps": ["step"],
      "finding_refs": ["exact finding title or index"]
    }
  ]
}
"""

HYPOTHESIS_SCHEMA = """
Return JSON via submit_result:
{
  "notes": "why these hypotheses",
  "hypotheses": [
    {
      "title": "short exploit name",
      "severity": "critical|high|medium",
      "focus": "what to prove, which functions, how it chains",
      "files": ["relative.py"],
      "steps": ["step"]
    }
  ]
}
At most 8. Each must be multi-step and reach data, privilege, or money.
Do not clone an existing finding title. Empty hypotheses only if the first wave already covered every source→sink edge.
"""

VERIFY_SCHEMA = """
Return JSON:
{
  "verdicts": [
    {
      "title": "exact title",
      "keep": true,
      "verified": true,
      "confidence": 0.0,
      "reason": ""
    }
  ]
}
"""


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:40] or "item"


async def emit(
    audit_id: str,
    *,
    agent: str | None,
    kind: str,
    message: str,
    payload: Any = None,
) -> dict[str, Any]:
    event = {
        "audit_id": audit_id,
        "ts": now(),
        "agent": agent,
        "kind": kind,
        "message": message,
        "payload": payload,
    }
    return insert_event(event)


def _is_fixture(path: Path) -> bool:
    try:
        return path.resolve() == FIXTURE_DIR.resolve()
    except OSError:
        return False


def create_audit(
    source: str,
    *,
    name: str | None = None,
    agent_ids: list[str] | None = None,
    focus: str = "",
    mode: str = "auto",
    base_ref: str | None = None,
) -> dict[str, Any]:
    seed_agents()
    audit_id = uuid.uuid4().hex[:12]
    if source.strip() in {"demo", "harbor", "harbor-shop"}:
        source = str(FIXTURE_DIR)
    source_kind, workdir = resolve_source(source, audit_id)
    roster = list_agents()
    available = {a["id"] for a in roster}
    if agent_ids:
        chosen = [aid for aid in agent_ids if aid in available]
    else:
        chosen = [a["id"] for a in roster if a["enabled"]]
    if "mapper" not in chosen:
        chosen = ["mapper", *chosen]
    if mode == "auto":
        mode = "demo" if _is_fixture(workdir) or not live_ready() else "live"
    if mode == "live" and not live_ready():
        raise RuntimeError("Live mode needs ZAI_API_KEY (GLM-5.3) or XAI_API_KEY")
    audit = {
        "id": audit_id,
        "name": name or workdir.name,
        "source": source,
        "source_kind": source_kind,
        "workdir": str(workdir),
        "mode": mode,
        "status": "pending",
        "focus": focus or "",
        "agent_ids": chosen,
        "created_at": now(),
    }
    insert_audit(audit)
    write_json(audit_id, "opts.json", {"base_ref": (base_ref or "").strip(), "focus": focus or ""})
    return get_audit(audit_id) or audit


def start_audit(audit_id: str) -> None:
    if audit_id in RUNNING:
        return
    try:
        loop = asyncio.get_running_loop()
        RUNNING[audit_id] = loop.create_task(run_audit(audit_id))
    except RuntimeError:
        thread = threading.Thread(target=lambda: asyncio.run(run_audit(audit_id)), daemon=True)
        RUNNING[audit_id] = thread  # type: ignore[assignment]
        thread.start()


def is_cancelled(audit_id: str) -> bool:
    if audit_id in CANCEL:
        return True
    audit = get_audit(audit_id)
    return bool(audit and audit["status"] == "cancelled")


def cancel_audit(audit_id: str) -> None:
    CANCEL.add(audit_id)
    audit = get_audit(audit_id)
    if audit and audit["status"] in {"pending", "running"}:
        update_audit(audit_id, status="cancelled", finished_at=now())
        insert_event(
            {
                "audit_id": audit_id,
                "ts": now(),
                "agent": None,
                "kind": "status",
                "message": "Audit cancelled.",
                "payload": None,
            }
        )
    task = RUNNING.get(audit_id)
    if isinstance(task, asyncio.Task):
        try:
            loop = task.get_loop()
            loop.call_soon_threadsafe(task.cancel)
        except Exception:
            task.cancel()


def _guard(audit_id: str) -> None:
    audit = get_audit(audit_id)
    if not audit:
        raise RuntimeError("audit vanished")
    if is_cancelled(audit_id):
        raise asyncio.CancelledError()


def _dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for finding in findings:
        ev = (finding.get("evidence") or [{}])[0]
        key = "|".join(
            [
                (finding.get("category") or ""),
                (ev.get("path") or ""),
                re.sub(r"[^a-z0-9]+", "", (finding.get("title") or "").lower())[:48],
            ]
        )
        prev = seen.get(key)
        if prev is None:
            seen[key] = finding
            order.append(key)
            continue
        if rank.get((finding.get("severity") or "info").lower(), 9) < rank.get(
            (prev.get("severity") or "info").lower(), 9
        ):
            seen[key] = finding
    return [seen[k] for k in order]


def _uncovered_routes(threat: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    table = threat.get("route_table") or []
    blob = " ".join(
        f"{f.get('title')} {f.get('summary')} {f.get('description')}" for f in findings
    ).lower()
    missing = []
    for row in table:
        path = str(row.get("path") or "")
        if path and path.lower() not in blob:
            missing.append(f"{row.get('method', 'ANY')} {path} ({row.get('file')})")
    return missing


def _enrich_evidence(workdir: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for finding in findings:
        evidence = []
        for ev in finding.get("evidence") or []:
            path = ev.get("path")
            if not path:
                continue
            try:
                text = read_file(workdir, path)
            except (OSError, ValueError, FileNotFoundError):
                continue
            start = max(1, int(ev.get("start_line") or 1))
            end = int(ev.get("end_line") or start + 8)
            lines = text.splitlines()
            start = min(start, max(1, len(lines)))
            end = min(max(start, end), len(lines))
            snippet = ev.get("snippet") or "\n".join(lines[start - 1 : end])
            evidence.append(
                {
                    "path": path,
                    "start_line": start,
                    "end_line": end,
                    "snippet": snippet,
                    "why": ev.get("why") or "",
                }
            )
        finding["evidence"] = evidence
    return findings


def _system_for(agent: dict[str, Any], extra: str) -> str:
    engine = f"{active_provider() or 'demo'}/{active_model()}"
    return (
        "You are a specialist agent in Vuln, a source-only code audit orchestrator. "
        "You reason like a pentester across files. You do not need a live URL. "
        "Never propose exploits against third-party systems. Stay inside the provided repo.\n"
        f"Engine: {engine}\n"
        f"Agent: {agent['name']}\nRole: {agent['role']}\nFocus:\n{agent['focus']}\n\n"
        f"{extra}"
    )


async def _call_agent(
    agent: dict[str, Any],
    system_extra: str,
    user: str,
    emit_fn: Callable,
    *,
    workdir: Path | None = None,
    index: dict[str, Any] | None = None,
    deep: bool = True,
    audit_id: str | None = None,
) -> dict[str, Any]:
    if audit_id:
        _guard(audit_id)
    system = _system_for(agent, system_extra)
    loop = asyncio.get_running_loop()
    async with _hunt_sem():
        if audit_id:
            _guard(audit_id)
        await emit_fn(
            agent=agent["id"],
            kind="think",
            message=f"{agent['name']} is hunting with {active_model()}.",
        )
        return await _run_agent_job(
            agent,
            system,
            user,
            emit_fn,
            workdir=workdir,
            index=index,
            deep=deep,
            audit_id=audit_id,
            loop=loop,
        )


async def _run_agent_job(
    agent: dict[str, Any],
    system: str,
    user: str,
    emit_fn: Callable,
    *,
    workdir: Path | None,
    index: dict[str, Any] | None,
    deep: bool,
    audit_id: str | None,
    loop: asyncio.AbstractEventLoop,
) -> dict[str, Any]:
    if deep and workdir is not None and index is not None:

        def on_event(kind: str, message: str, payload: Any = None) -> None:
            if audit_id and is_cancelled(audit_id):
                return
            fut = asyncio.run_coroutine_threadsafe(
                emit_fn(agent=agent["id"], kind=kind, message=message, payload=payload),
                loop,
            )
            try:
                fut.result(timeout=15)
            except Exception:
                pass

        return await loop.run_in_executor(
            _HUNT_POOL,
            lambda: hunt(
                system,
                user,
                workdir,
                index,
                on_event=on_event,
                max_rounds=HUNT_ROUNDS,
                should_stop=(lambda: is_cancelled(audit_id)) if audit_id else None,
            ),
        )
    return await loop.run_in_executor(_HUNT_POOL, lambda: complete_json(system, user))


async def run_audit(audit_id: str) -> None:
    seed_agents()
    try:
        update_audit(audit_id, status="running", started_at=now(), error=None)
        await emit(audit_id, agent=None, kind="status", message="Audit started.")
        audit = get_audit(audit_id)
        if not audit:
            raise RuntimeError("unknown audit")
        workdir = Path(audit["workdir"])
        await emit(audit_id, agent="mapper", kind="index", message=f"Indexing {workdir.name}…")
        loop = asyncio.get_running_loop()

        def on_index(info: dict[str, Any]) -> None:
            path = info.get("path") or ""
            msg = f"{info.get('files', 0)} files · {info.get('routes', 0)} routes · {path}"
            fut = asyncio.run_coroutine_threadsafe(
                emit(audit_id, agent="mapper", kind="index", message=msg, payload=info),
                loop,
            )
            try:
                fut.result(timeout=5)
            except Exception:
                pass

        index = await asyncio.to_thread(index_repo, workdir, audit["name"], on_index)
        update_audit(audit_id, index_json=index)
        langs = ", ".join(f"{k} ({v})" for k, v in list(index["languages"].items())[:6]) or "unknown"
        skipped = index.get("skipped_dirs") or []
        skip_note = f" · skipped {len(skipped)} junk dirs" if skipped else ""
        await emit(
            audit_id,
            agent="mapper",
            kind="index",
            message=f"Index complete · {index['indexed']} files · {langs} · {len(index['routes'])} routes{skip_note}",
            payload={
                "file_count": index["file_count"],
                "routes": len(index["routes"]),
                "done": True,
                "skipped": skipped[:20],
            },
        )
        _guard(audit_id)

        if audit["mode"] == "demo":
            await _run_demo(audit_id, workdir, index)
        else:
            await _run_live(audit_id, workdir, index, audit)

        if is_cancelled(audit_id):
            raise asyncio.CancelledError()
        update_audit(audit_id, status="completed", finished_at=now())
        await emit(audit_id, agent=None, kind="status", message="Audit completed.")
    except asyncio.CancelledError:
        if not is_cancelled(audit_id):
            update_audit(audit_id, status="cancelled", finished_at=now())
            await emit(audit_id, agent=None, kind="status", message="Audit cancelled.")
        elif get_audit(audit_id) and get_audit(audit_id)["status"] != "cancelled":
            update_audit(audit_id, status="cancelled", finished_at=now())
    except Exception as exc:
        update_audit(audit_id, status="failed", finished_at=now(), error=str(exc))
        await emit(
            audit_id,
            agent=None,
            kind="error",
            message=f"Audit failed: {exc}",
            payload={"trace": traceback.format_exc()[-2000:]},
        )
    finally:
        CANCEL.discard(audit_id)
        RUNNING.pop(audit_id, None)


async def _run_demo(audit_id: str, workdir: Path, index: dict[str, Any]) -> None:
    async def _emit(agent: str | None, kind: str, message: str, payload: Any = None) -> None:
        await emit(audit_id, agent=agent, kind=kind, message=message, payload=payload)

    update_audit(audit_id, threat_model=DEMO_THREAT_MODEL)
    init_coverage(
        audit_id,
        [
            {"method": e.split(" ", 1)[0], "path": e.split(" ", 1)[-1], "file": ""}
            for e in (DEMO_THREAT_MODEL.get("entry_points") or [])
            if " " in e
        ],
    )
    await play_demo_events(_emit)
    findings = materialize_findings(workdir, audit_id)
    for finding in findings:
        insert_finding(finding)
        mark_finding_routes(audit_id, finding.get("agent") or "demo", [finding])
        await emit(
            audit_id,
            agent=finding["agent"],
            kind="finding",
            message=finding["title"],
            payload={"id": finding["id"], "severity": finding["severity"]},
        )
    for chain in materialize_chains(audit_id):
        insert_chain(chain)
        await emit(audit_id, agent="chain", kind="chain", message=chain["title"])
    _ = index


async def _run_live(audit_id: str, workdir: Path, index: dict[str, Any], audit: dict[str, Any]) -> None:
    agents = {a["id"]: a for a in list_agents()}
    chosen = [agents[i] for i in audit["agent_ids"] if i in agents]
    mapper = next((a for a in chosen if a["phase"] == "map"), get_agent("mapper"))
    specialists = [a for a in chosen if a["phase"] == "specialist"]
    sweeper = next((a for a in chosen if a["id"] == "sweeper"), get_agent("sweeper"))
    conductor = next((a for a in chosen if a["id"] == "conductor"), get_agent("conductor"))
    joiner = next((a for a in chosen if a["id"] == "chain"), get_agent("chain"))
    verifier = next((a for a in chosen if a["id"] == "verifier"), get_agent("verifier"))

    tree = "\n".join(index["tree"][:400])
    routes = "\n".join(
        f"{r.get('method', 'ANY')} {r.get('path')} ({r.get('file')})" for r in index["routes"][:120]
    )
    await emit(audit_id, agent="mapper", kind="index", message="Scanning for static leads…")
    leads = await asyncio.to_thread(static_leads, workdir, index)
    await emit(audit_id, agent="mapper", kind="index", message="Mapping sources and sinks…")
    flow = await asyncio.to_thread(extract_surface, workdir, index)
    await emit(audit_id, agent="mapper", kind="index", message="Building call/taint graph…")
    graph = await asyncio.to_thread(build_graph, workdir, index)
    write_json(audit_id, "graph.json", graph)
    opts = read_json(audit_id, "opts.json", {})
    base_ref = (opts or {}).get("base_ref") or None
    diff = await asyncio.to_thread(git_changed_files, workdir, base_ref)
    write_json(audit_id, "diff.json", diff)
    await emit(audit_id, agent="mapper", kind="index", message="Packing attack surface…")
    extra_paths = list(diff.get("files") or [])
    packed = await asyncio.to_thread(pack_attack_surface, workdir, index, extra_paths)
    focus = audit.get("focus") or (
        "Full adversarial audit. Trace every entry point into the data layer and out to sinks. "
        "Hunt multi-step chains (auth bypass → object access → file/SQLi/money). "
        "Missing owner/role/tenant checks are bugs even when the user is logged in."
    )
    deep = audit.get("mode") != "demo"
    lead_block = "\n".join(f"- {item}" for item in leads) or "(none)"
    flow_block = (
        "SOURCES (attacker-controlled):\n"
        + "\n".join(f"- {s}" for s in (flow.get("sources") or [])[:40])
        + "\nSINKS:\n"
        + "\n".join(f"- {s}" for s in (flow.get("sinks") or [])[:40])
    )
    taint = graph.get("taint") or []
    graph_block = (
        "CALL/TAINT EDGES (follow these):\n"
        + "\n".join(f"- {t}" for t in taint[:30])
        + "\nCross-file calls:\n"
        + "\n".join(
            f"- {c.get('from')} --{c.get('symbol')}--> {c.get('to')}"
            for c in (graph.get("calls") or [])[:25]
        )
    )
    changed = diff.get("files") or []
    diff_block = ""
    if diff.get("available") and changed:
        diff_block = (
            f"\nDIFF vs {diff.get('base')} (prioritize these files):\n"
            + "\n".join(f"- {p}" for p in changed[:40])
            + "\n"
        )
        focus = f"{focus}\nChanged files vs {diff.get('base')}: {', '.join(changed[:20])}"

    await emit(
        audit_id,
        agent="mapper",
        kind="note",
        message=f"{len(leads)} leads · {len(taint)} taint edges · {len(changed)} changed files.",
    )

    spec_pack = packed
    route_table = [
        {
            "method": r.get("method"),
            "path": r.get("path"),
            "file": r.get("file"),
            "auth_observed": "unknown",
            "auth_expected": "unknown",
            "risk": "medium",
        }
        for r in index.get("routes") or []
    ]
    threat: dict[str, Any] = {"route_table": route_table, "summary": "mapping in parallel"}
    init_coverage(audit_id, route_table)

    mapper_user = (
        f"Repo: {audit['name']}\nOperator focus: {focus}\n\n"
        f"Languages: {index['languages']}\n\nExtracted routes:\n{routes or '(none extracted)'}\n\n"
        f"Static leads (confirm or reject with evidence):\n{lead_block}\n\n"
        f"{flow_block}\n\n{graph_block}\n{diff_block}\n"
        f"Tree:\n{tree}\n\nSource (use tools for anything missing):\n{packed}\n"
    )

    async def run_specialist(agent: dict[str, Any], extra: str = "") -> list[dict[str, Any]]:
        _guard(audit_id)
        pad = snapshot_text(audit_id)
        user = (
            f"Repo: {audit['name']}\nOperator focus: {focus}\n\n"
            f"SCRATCHPAD (shared — do not re-prove these claims):\n{pad}\n\n"
            f"Threat model:\n{threat}\n\n"
            f"Route table:\n{route_table}\n\n"
            f"Static leads (must confirm or reject):\n{lead_block}\n\n"
            f"{flow_block}\n\n{graph_block}\n{diff_block}\n"
            f"{extra}"
            f"Source (use tools to chase callees and sinks):\n{spec_pack}\n"
        )
        try:
            data = await _call_agent(
                agent,
                FINDINGS_SCHEMA,
                user,
                lambda **kw: emit(audit_id, **kw),
                workdir=workdir,
                index=index,
                deep=deep,
                audit_id=audit_id,
            )
        except LLMError as exc:
            await emit(audit_id, agent=agent["id"], kind="error", message=str(exc))
            return []
        notes = data.get("notes")
        if notes:
            await emit(audit_id, agent=agent["id"], kind="note", message=str(notes)[:280])
        findings = data.get("findings") or []
        for finding in findings:
            finding["agent"] = agent["id"]
        merge_reviews(audit_id, agent["id"], data.get("reviewed_routes") or [])
        mark_finding_routes(audit_id, agent["id"], findings)
        if data.get("notes"):
            append_claim(audit_id, agent["id"], str(data["notes"])[:400])
        elif findings:
            append_claim(audit_id, agent["id"], "; ".join(f.get("title") or "" for f in findings[:5]))
        cov = coverage_summary(audit_id)
        await emit(
            audit_id,
            agent=agent["id"],
            kind="note",
            message=f"Coverage {cov['reviewed']}/{cov['total']} routes ({cov['open']} still open).",
            payload=cov,
        )
        return findings

    await emit(
        audit_id,
        agent=None,
        kind="note",
        message=f"Launching mapper + {len(specialists)} specialists ({HUNT_CONCURRENCY} at a time).",
    )
    wave = await asyncio.gather(
        _call_agent(
            mapper or {"id": "mapper", "name": "Mapper", "role": "context", "focus": ""},
            MAPPER_SCHEMA,
            mapper_user,
            lambda **kw: emit(audit_id, **kw),
            workdir=workdir,
            index=index,
            deep=deep,
            audit_id=audit_id,
        ),
        *[run_specialist(a) for a in specialists],
        return_exceptions=True,
    )
    mapped = wave[0]
    if isinstance(mapped, Exception):
        await emit(audit_id, agent="mapper", kind="error", message=str(mapped))
    elif isinstance(mapped, dict):
        threat = mapped
        if not threat.get("route_table"):
            threat["route_table"] = route_table
        update_audit(audit_id, threat_model=threat)
        await emit(
            audit_id,
            agent="mapper",
            kind="note",
            message=threat.get("summary", "Threat model ready.")[:280],
            payload=threat,
        )

    raw: list[dict[str, Any]] = []
    for batch in wave[1:]:
        if isinstance(batch, Exception):
            await emit(audit_id, agent=None, kind="error", message=str(batch))
            continue
        raw.extend(batch)

    raw = [f for f in raw if f.get("title") and f.get("summary")]
    raw = _enrich_evidence(workdir, raw)
    raw = _dedup_findings(raw)
    mark_finding_routes(audit_id, "wave1", raw)
    _guard(audit_id)

    open_routes = uncovered_keys(audit_id)
    if open_routes:
        chunks: list[list[dict[str, Any]]] = [
            open_routes[i : i + 4] for i in range(0, len(open_routes), 4)
        ][:8]
        await emit(
            audit_id,
            agent="mapper",
            kind="note",
            message=f"{len(open_routes)} routes unreviewed — {len(chunks)} coverage hunts.",
            payload=coverage_summary(audit_id),
        )

        async def run_coverage(i: int, chunk: list[dict[str, Any]]) -> list[dict[str, Any]]:
            ghost = {
                "id": f"cov{i}",
                "name": f"Coverage {i}",
                "role": "specialist",
                "focus": (
                    "You own ONLY the assigned routes. For each: read the handler and its "
                    "callees. File a finding or mark clean with why. reviewed_routes is required."
                ),
            }
            extra = (
                "ASSIGNED ROUTES (mandatory reviewed_routes):\n"
                + "\n".join(
                    f"- {r.get('method')} {r.get('path')} ({r.get('file')})" for r in chunk
                )
                + "\n"
            )
            return await run_specialist(ghost, extra)

        cov_batches = await asyncio.gather(
            *[run_coverage(i, ch) for i, ch in enumerate(chunks, 1)],
            return_exceptions=True,
        )
        for batch in cov_batches:
            if isinstance(batch, Exception):
                await emit(audit_id, agent="cov", kind="error", message=str(batch))
                continue
            raw.extend(batch)
        raw = [f for f in raw if f.get("title") and f.get("summary")]
        raw = _enrich_evidence(workdir, raw)
        raw = _dedup_findings(raw)

    if sweeper and (sweeper.get("enabled", True)):
        _guard(audit_id)
        still_open = uncovered_keys(audit_id)
        prior = [f.get("title") for f in raw]
        extra = (
            f"Prior findings (do not repeat unless you have a new sink):\n{prior}\n\n"
            f"Scratchpad:\n{snapshot_text(audit_id)}\n\n"
            f"Routes still open:\n{still_open or '(none)'}\n\n"
        )
        try:
            more = await run_specialist(sweeper, extra)
            raw.extend(more)
            raw = [f for f in raw if f.get("title") and f.get("summary")]
            raw = _enrich_evidence(workdir, raw)
            raw = _dedup_findings(raw)
        except LLMError as exc:
            await emit(audit_id, agent="sweeper", kind="error", message=str(exc))

    if conductor and conductor.get("enabled", True):
        _guard(audit_id)
        uncovered = _uncovered_routes(threat, raw)
        hypo_user = (
            f"Repo: {audit['name']}\n"
            f"Scratchpad:\n{snapshot_text(audit_id)}\n\n"
            f"Threat model:\n{threat}\n\n"
            f"Existing findings:\n{[f.get('title') for f in raw]}\n\n"
            f"Uncovered routes:\n{uncovered_keys(audit_id) or uncovered or '(none)'}\n\n"
            f"{flow_block}\n\n{graph_block}\n{diff_block}\n"
            f"Static leads:\n{lead_block}\n"
        )
        try:
            hypo = await _call_agent(
                conductor,
                HYPOTHESIS_SCHEMA,
                hypo_user,
                lambda **kw: emit(audit_id, **kw),
                workdir=workdir,
                index=index,
                deep=deep,
                audit_id=audit_id,
            )
        except LLMError as exc:
            await emit(audit_id, agent="conductor", kind="error", message=str(exc))
            hypo = {}
        hypotheses = (hypo.get("hypotheses") or [])[:8]
        if hypotheses:
            await emit(
                audit_id,
                agent="conductor",
                kind="note",
                message=f"{len(hypotheses)} exploit hypotheses queued.",
            )

            async def run_hypothesis(i: int, item: dict[str, Any]) -> list[dict[str, Any]]:
                ghost = {
                    "id": f"hyp{i}",
                    "name": (item.get("title") or f"Hypothesis {i}")[:48],
                    "role": "specialist",
                    "focus": (
                        f"{item.get('focus') or ''}\n"
                        f"Steps: {item.get('steps')}\n"
                        f"Read first: {item.get('files')}\n"
                        "Prove this chain with file:line evidence or disprove it."
                    ),
                }
                extra = (
                    f"HYPOTHESIS TO PROVE:\n{item}\n"
                    f"Prior titles (do not clone):\n{[f.get('title') for f in raw]}\n\n"
                )
                return await run_specialist(ghost, extra)

            hyp_batches = await asyncio.gather(
                *[run_hypothesis(i, h) for i, h in enumerate(hypotheses, 1)],
                return_exceptions=True,
            )
            for batch in hyp_batches:
                if isinstance(batch, Exception):
                    await emit(audit_id, agent="conductor", kind="error", message=str(batch))
                    continue
                raw.extend(batch)
            raw = [f for f in raw if f.get("title") and f.get("summary")]
            raw = _enrich_evidence(workdir, raw)
            raw = _dedup_findings(raw)

    if joiner and raw:
        chain_user = (
            f"Findings:\n{raw}\n\nThreat model:\n{threat}\n\n{flow_block}\n"
            "Build the worst realistic chains that reach data, privilege, or money."
        )
        try:
            chain_data = await _call_agent(
                joiner,
                CHAIN_SCHEMA,
                chain_user,
                lambda **kw: emit(audit_id, **kw),
                audit_id=audit_id,
            )
        except LLMError as exc:
            await emit(audit_id, agent="chain", kind="error", message=str(exc))
            chain_data = {"chains": []}
    else:
        chain_data = {"chains": []}

    kept = raw
    if verifier and raw:
        cited = []
        for finding in raw:
            cited.append(
                {
                    "title": finding.get("title"),
                    "evidence": finding.get("evidence"),
                    "summary": finding.get("summary"),
                    "severity": finding.get("severity"),
                }
            )
        try:
            verdicts = await _call_agent(
                verifier,
                VERIFY_SCHEMA,
                (
                    "Default KEEP. Drop only if the cited path is missing or you can quote "
                    "the real guard in the same function.\n\n"
                    f"{cited}"
                ),
                lambda **kw: emit(audit_id, **kw),
                workdir=workdir,
                index=index,
                deep=False,
                audit_id=audit_id,
            )
            by_title = {v.get("title"): v for v in verdicts.get("verdicts") or []}
            next_kept = []
            for finding in raw:
                has_file = bool(finding.get("evidence"))
                verdict = by_title.get(finding.get("title"))
                if verdict and not verdict.get("keep", True) and not has_file:
                    await emit(
                        audit_id,
                        agent="verifier",
                        kind="note",
                        message=f"Dropped: {finding.get('title')} — {verdict.get('reason', '')}"[:280],
                    )
                    continue
                if verdict and not verdict.get("keep", True) and has_file:
                    await emit(
                        audit_id,
                        agent="verifier",
                        kind="note",
                        message=f"Kept despite challenge (has evidence): {finding.get('title')}"[:280],
                    )
                if verdict:
                    finding["verified"] = bool(verdict.get("verified", True) or has_file)
                    if verdict.get("confidence") is not None:
                        finding["confidence"] = verdict["confidence"]
                else:
                    finding["verified"] = True
                next_kept.append(finding)
            kept = next_kept
        except LLMError as exc:
            await emit(audit_id, agent="verifier", kind="error", message=str(exc))
            for finding in kept:
                finding.setdefault("verified", True)

    _guard(audit_id)

    title_to_id: dict[str, str] = {}
    for finding in kept:
        fid = f"{audit_id}-{_slug(finding['title'])}-{uuid.uuid4().hex[:4]}"
        title_to_id[finding["title"]] = fid
        record = {
            "id": fid,
            "audit_id": audit_id,
            "title": finding["title"],
            "severity": (finding.get("severity") or "medium").lower(),
            "category": finding.get("category") or "other",
            "cwe": finding.get("cwe"),
            "summary": finding.get("summary") or "",
            "description": finding.get("description") or finding.get("summary") or "",
            "root_cause": finding.get("root_cause") or "",
            "impact": finding.get("impact") or "",
            "remediation": finding.get("remediation") or "",
            "attack_path": finding.get("attack_path") or [],
            "evidence": finding.get("evidence") or [],
            "confidence": float(finding.get("confidence") or 0.55),
            "verified": bool(finding.get("verified", True)),
            "agent": finding.get("agent") or "specialist",
            "status": "open",
            "owasp": finding.get("owasp"),
            "attacker": finding.get("attacker"),
            "preconditions": finding.get("preconditions"),
            "affected_routes": finding.get("affected_routes"),
            "blast_radius": finding.get("blast_radius"),
            "why_sast_misses": finding.get("why_sast_misses"),
            "confidence_rationale": finding.get("confidence_rationale"),
            "fix_tests": finding.get("fix_tests"),
            "details": finding.get("details"),
        }
        insert_finding(record)
        await emit(
            audit_id,
            agent=record["agent"],
            kind="finding",
            message=record["title"],
            payload={"id": fid, "severity": record["severity"]},
        )

    for idx, chain in enumerate(chain_data.get("chains") or []):
        refs = chain.get("finding_refs") or []
        fids = []
        for ref in refs:
            if ref in title_to_id:
                fids.append(title_to_id[ref])
            elif isinstance(ref, int) and 0 <= ref < len(kept):
                fids.append(title_to_id[kept[ref]["title"]])
        cid = f"{audit_id}-chain-{idx}"
        insert_chain(
            {
                "id": cid,
                "audit_id": audit_id,
                "title": chain.get("title") or "Attack chain",
                "severity": (chain.get("severity") or "high").lower(),
                "summary": chain.get("summary") or "",
                "steps": chain.get("steps") or [],
                "finding_ids": fids,
            }
        )
        await emit(audit_id, agent="chain", kind="chain", message=chain.get("title") or "Attack chain")
