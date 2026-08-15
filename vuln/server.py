from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from concurrent.futures import ThreadPoolExecutor

from .config import (
    FIXTURE_DIR,
    HUNT_CONCURRENCY,
    HUNT_WORKERS,
    WEB_DIR,
    active_model,
    active_provider,
    live_ready,
    set_runtime_key,
    set_runtime_provider,
    xai_key,
    zai_key,
)
from .ingest import read_file, skip_dir_name
from .scratch import coverage_summary
from .orchestrator import cancel_audit, create_audit, start_audit
from .store import (
    delete_custom_agent,
    get_audit,
    get_finding,
    list_agents,
    list_audits,
    list_chains,
    list_events,
    list_findings,
    overview,
    seed_agents,
    set_agent_enabled,
    set_finding_status,
    upsert_custom_agent,
)

app = FastAPI(title="Vuln", version=__version__)


class NewAudit(BaseModel):
    source: str = Field(..., description="Local path, git URL, or 'demo'")
    name: str | None = None
    agent_ids: list[str] | None = None
    focus: str = ""
    mode: str = "auto"
    base_ref: str | None = None


class AgentIn(BaseModel):
    id: str
    name: str
    description: str = ""
    focus: str
    enabled: bool = True


class AgentPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    description: str | None = None
    focus: str | None = None


class FindingPatch(BaseModel):
    status: str


class SettingsIn(BaseModel):
    provider: str | None = None
    zai_key: str | None = None
    xai_key: str | None = None


@app.on_event("startup")
def _startup() -> None:
    seed_agents()
    loop = asyncio.get_event_loop()
    loop.set_default_executor(
        ThreadPoolExecutor(max_workers=HUNT_CONCURRENCY, thread_name_prefix="vuln")
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    provider = active_provider()
    return {
        "ok": True,
        "version": __version__,
        "live": live_ready(),
        "provider": provider,
        "model": active_model() if provider else None,
        "zai": bool(zai_key()),
        "xai": bool(xai_key()),
        "demo_repo": str(FIXTURE_DIR),
        "cwd": str(Path.cwd()),
        "home": str(Path.home()),
        "workers": HUNT_CONCURRENCY,
    }


@app.get("/api/overview")
def api_overview() -> dict[str, Any]:
    return overview()


@app.get("/api/settings")
def api_get_settings() -> dict[str, Any]:
    h = health()
    return {
        "provider": h["provider"] or "auto",
        "zai": h["zai"],
        "xai": h["xai"],
        "model": h["model"],
    }


@app.post("/api/settings")
def api_set_settings(body: SettingsIn) -> dict[str, Any]:
    if body.provider is not None:
        try:
            set_runtime_provider(body.provider)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    if body.zai_key is not None:
        set_runtime_key("zai", body.zai_key)
    if body.xai_key is not None:
        set_runtime_key("xai", body.xai_key)
    return api_get_settings()


@app.get("/api/browse")
def api_browse(path: str | None = Query(default=None)) -> dict[str, Any]:
    raw = (path or str(Path.home())).strip() or str(Path.home())
    target = Path(raw).expanduser()
    try:
        target = target.resolve()
    except OSError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not target.exists() or not target.is_dir():
        raise HTTPException(404, f"Not a directory: {target}")
    try:
        children = list(target.iterdir())
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    dirs: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    for child in sorted(children, key=lambda p: p.name.lower()):
        if skip_dir_name(child.name):
            continue
        try:
            is_dir = child.is_dir()
        except OSError:
            continue
        item = {"name": child.name, "path": str(child)}
        if is_dir:
            dirs.append(item)
        else:
            files.append(item)
    return {
        "path": str(target),
        "parent": str(target.parent),
        "dirs": dirs[:200],
        "files": files[:80],
    }


@app.get("/api/agents")
def api_agents() -> list[dict[str, Any]]:
    return list_agents()


@app.post("/api/agents")
def api_create_agent(body: AgentIn) -> dict[str, Any]:
    if body.id in {"mapper", "chain", "verifier"}:
        raise HTTPException(400, "That id is reserved")
    return upsert_custom_agent(body.model_dump())


@app.patch("/api/agents/{agent_id}")
def api_patch_agent(agent_id: str, body: AgentPatch) -> dict[str, Any]:
    current = next((a for a in list_agents() if a["id"] == agent_id), None)
    if not current:
        raise HTTPException(404, "Unknown agent")
    if body.enabled is not None:
        current = set_agent_enabled(agent_id, body.enabled) or current
    if not current["builtin"] and any(v is not None for v in (body.name, body.description, body.focus)):
        current = upsert_custom_agent(
            {
                "id": agent_id,
                "name": body.name or current["name"],
                "description": body.description if body.description is not None else current["description"],
                "focus": body.focus or current["focus"],
                "enabled": current["enabled"],
            }
        )
    return current


@app.delete("/api/agents/{agent_id}")
def api_delete_agent(agent_id: str) -> dict[str, bool]:
    if not delete_custom_agent(agent_id):
        raise HTTPException(400, "Cannot delete a built-in agent")
    return {"ok": True}


@app.get("/api/audits")
def api_audits() -> list[dict[str, Any]]:
    return list_audits()


@app.post("/api/audits")
async def api_create_audit(body: NewAudit) -> dict[str, Any]:
    try:
        audit = create_audit(
            body.source,
            name=body.name,
            agent_ids=body.agent_ids,
            focus=body.focus,
            mode=body.mode,
            base_ref=body.base_ref,
        )
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    start_audit(audit["id"])
    return audit


@app.get("/api/audits/{audit_id}")
def api_get_audit(audit_id: str) -> dict[str, Any]:
    audit = get_audit(audit_id)
    if not audit:
        raise HTTPException(404, "Unknown audit")
    audit["findings"] = list_findings(audit_id)
    audit["chains"] = list_chains(audit_id)
    audit["coverage"] = coverage_summary(audit_id)
    return audit


@app.post("/api/audits/{audit_id}/cancel")
async def api_cancel(audit_id: str) -> dict[str, Any]:
    if not get_audit(audit_id):
        raise HTTPException(404, "Unknown audit")
    cancel_audit(audit_id)
    return {"ok": True, "status": "cancelled"}


@app.get("/api/audits/{audit_id}/findings")
def api_findings(audit_id: str) -> list[dict[str, Any]]:
    if not get_audit(audit_id):
        raise HTTPException(404, "Unknown audit")
    return list_findings(audit_id)


@app.get("/api/audits/{audit_id}/findings/{finding_id}")
def api_finding(audit_id: str, finding_id: str) -> dict[str, Any]:
    finding = get_finding(finding_id)
    if not finding or finding["audit_id"] != audit_id:
        raise HTTPException(404, "Unknown finding")
    return finding


@app.patch("/api/audits/{audit_id}/findings/{finding_id}")
def api_patch_finding(audit_id: str, finding_id: str, body: FindingPatch) -> dict[str, Any]:
    finding = get_finding(finding_id)
    if not finding or finding["audit_id"] != audit_id:
        raise HTTPException(404, "Unknown finding")
    if body.status not in {"open", "accepted", "ignored", "fixed"}:
        raise HTTPException(400, "status must be open|accepted|ignored|fixed")
    return set_finding_status(finding_id, body.status) or finding


@app.get("/api/audits/{audit_id}/files")
def api_file(audit_id: str, path: str) -> dict[str, Any]:
    audit = get_audit(audit_id)
    if not audit:
        raise HTTPException(404, "Unknown audit")
    try:
        text = read_file(Path(audit["workdir"]), path)
    except (OSError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"path": path, "content": text}


@app.get("/api/audits/{audit_id}/report.md")
def api_report(audit_id: str) -> PlainTextResponse:
    audit = get_audit(audit_id)
    if not audit:
        raise HTTPException(404, "Unknown audit")
    findings = list_findings(audit_id)
    chains = list_chains(audit_id)
    lines = [
        f"# Vuln audit — {audit['name']}",
        "",
        f"- Status: {audit['status']}",
        f"- Mode: {audit['mode']}",
        f"- Source: {audit['source']}",
        f"- Started: {audit.get('started_at') or '—'}",
        "",
        "## Threat model",
        "",
    ]
    tm = audit.get("threat_model") or {}
    if isinstance(tm, dict):
        lines.append(tm.get("summary") or "_No threat model._")
        if tm.get("hunt_leads"):
            lines += ["", "### Hunt leads", ""]
            lines += [f"- {lead}" for lead in tm["hunt_leads"]]
    lines += ["", "## Attack chains", ""]
    if not chains:
        lines.append("_None._")
    for chain in chains:
        lines += [f"### {chain['title']} ({chain['severity']})", "", chain["summary"], ""]
        lines += [f"{i}. {step}" for i, step in enumerate(chain["steps"], 1)]
        lines.append("")
    lines += ["## Findings", ""]
    for finding in findings:
        lines += [
            f"### [{finding['severity']}] {finding['title']}",
            "",
            f"- Category: {finding['category']}",
            f"- CWE: {finding.get('cwe') or '—'}",
            f"- Agent: {finding['agent']}",
            f"- Confidence: {finding['confidence']}",
            "",
            finding["summary"],
            "",
            finding.get("description") or "",
            "",
        ]
        det = finding.get("details") or {}
        if det.get("attacker"):
            lines += [f"**Attacker.** {det['attacker']}", ""]
        if det.get("owasp"):
            lines += [f"**OWASP.** {det['owasp']}", ""]
        if det.get("preconditions"):
            lines += ["**Preconditions.**", ""]
            lines += [f"- {p}" for p in det["preconditions"]]
            lines += [""]
        if det.get("affected_routes"):
            lines += ["**Affected routes.** " + ", ".join(det["affected_routes"]), ""]
        if det.get("blast_radius"):
            lines += [f"**Blast radius.** {det['blast_radius']}", ""]
        if det.get("why_sast_misses"):
            lines += [f"**Why SAST misses this.** {det['why_sast_misses']}", ""]
        if det.get("confidence_rationale"):
            lines += [f"**Confidence.** {det['confidence_rationale']}", ""]
        if det.get("fix_tests"):
            lines += ["**Regression tests.**", ""]
            lines += [f"- {t}" for t in det["fix_tests"]]
            lines += [""]
        lines += [
            "**Root cause.** " + finding["root_cause"],
            "",
            "**Impact.** " + finding["impact"],
            "",
            "**Remediation.** " + finding["remediation"],
            "",
            "**Attack path.**",
            "",
        ]
        lines += [f"{i}. {step}" for i, step in enumerate(finding["attack_path"], 1)]
        lines += ["", "**Evidence.**", ""]
        for ev in finding["evidence"]:
            lines += [
                f"`{ev['path']}:{ev['start_line']}-{ev['end_line']}` — {ev.get('why') or ''}",
                "",
                "```",
                ev.get("snippet") or "",
                "```",
                "",
            ]
    return PlainTextResponse("\n".join(lines), media_type="text/markdown")


@app.get("/api/audits/{audit_id}/coverage")
def api_coverage(audit_id: str) -> dict[str, Any]:
    if not get_audit(audit_id):
        raise HTTPException(404, "Unknown audit")
    return coverage_summary(audit_id)


@app.get("/api/audits/{audit_id}/log")
def api_log(audit_id: str) -> list[dict[str, Any]]:
    if not get_audit(audit_id):
        raise HTTPException(404, "Unknown audit")
    return list_events(audit_id)


@app.get("/api/audits/{audit_id}/events")
async def api_events(audit_id: str, after: int = 0) -> StreamingResponse:
    if not get_audit(audit_id):
        raise HTTPException(404, "Unknown audit")

    async def gen():
        cursor = after
        idle = 0
        while True:
            batch = list_events(audit_id, cursor)
            for event in batch:
                cursor = event["id"]
                idle = 0
                yield f"data: {__import__('json').dumps(event)}\n\n"
            audit = get_audit(audit_id)
            if audit and audit["status"] in {"completed", "failed", "cancelled"} and not batch:
                yield "event: done\ndata: {}\n\n"
                break
            idle += 1
            if idle > 600:
                break
            await asyncio.sleep(0.35)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")
