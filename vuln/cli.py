from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import FIXTURE_DIR, HOST, PORT
from .orchestrator import create_audit, run_audit
from .store import get_audit, list_findings, seed_agents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vuln",
        description="Vuln — orchestrate agents to audit source like a pentester.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="Start the audit console")
    serve.add_argument("--host", default=HOST)
    serve.add_argument("--port", type=int, default=PORT)

    audit = sub.add_parser("audit", help="Run an audit in the foreground")
    audit.add_argument("source", help="Local path, git URL, or 'demo'")
    audit.add_argument("--name")
    audit.add_argument("--focus", default="")
    audit.add_argument("--mode", default="auto", choices=["auto", "live", "demo"])
    audit.add_argument("--agents", help="Comma-separated agent ids")
    audit.add_argument("--base", help="Git ref to diff against (main, origin/main, SHA)")
    audit.add_argument("--json", action="store_true")

    sub.add_parser("demo", help="Audit the bundled Harbor Shop fixture")

    args = parser.parse_args(argv)
    seed_agents()

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("vuln.server:app", host=args.host, port=args.port, reload=False)
        return 0

    source = str(FIXTURE_DIR) if args.cmd == "demo" else args.source
    agent_ids = None
    if getattr(args, "agents", None):
        agent_ids = [a.strip() for a in args.agents.split(",") if a.strip()]
    record = create_audit(
        source,
        name=getattr(args, "name", None),
        agent_ids=agent_ids,
        focus=getattr(args, "focus", "") or "",
        mode="demo" if args.cmd == "demo" else getattr(args, "mode", "auto"),
        base_ref=getattr(args, "base", None),
    )
    print(f"audit {record['id']}  mode={record['mode']}  {record['name']}", file=sys.stderr)
    import asyncio

    asyncio.run(run_audit(record["id"]))
    done = get_audit(record["id"])
    findings = list_findings(record["id"])
    if getattr(args, "json", False) or args.cmd == "audit" and getattr(args, "json", False):
        print(json.dumps({"audit": done, "findings": findings}, indent=2))
    else:
        status = done["status"] if done else "unknown"
        print(f"status {status}  findings {len(findings)}", file=sys.stderr)
        for finding in findings:
            print(f"[{finding['severity']:8}] {finding['title']}")
        if done:
            print(f"report: /api/audits/{done['id']}/report.md", file=sys.stderr)
    return 0 if done and done["status"] == "completed" else 1


def serve() -> None:
    sys.exit(main(["serve", *sys.argv[1:]]))
