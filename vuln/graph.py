"""Lightweight call + taint map. Not a compiler — enough to force cross-file hunts."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .config import MAX_FILE_BYTES
from .surface import SINK_PATTERNS, SOURCE_PATTERNS

DEF_RX = re.compile(
    r"""^\s*(?:export\s+)?(?:async\s+)?(?:pub(?:lic|lic\(crate\))?\s+)?(?:static\s+)?(?:def|function|fn|func)\s+([A-Za-z_][\w]*)\s*\(""",
    re.M,
)
ASSIGN_FN_RX = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(?:async\s*)?\(""",
    re.M,
)
CALL_RX = re.compile(r"""\b([A-Za-z_][\w]*)\s*\(""")
SKIP_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "await",
    "print",
    "len",
    "str",
    "int",
    "range",
    "super",
    "typeof",
    "new",
}


def _read(workdir: Path, rel: str) -> str:
    target = (workdir / rel).resolve()
    if not str(target).startswith(str(workdir.resolve())) or not target.is_file():
        return ""
    data = target.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def build_graph(workdir: Path, index: dict[str, Any], limit_files: int = 80) -> dict[str, Any]:
    workdir = workdir.resolve()
    functions: list[dict[str, Any]] = []
    by_name: dict[str, list[str]] = {}
    file_tags: dict[str, set[str]] = {}
    src_rx = [re.compile(p, re.I) for p, _ in SOURCE_PATTERNS]
    sink_rx = [re.compile(p, re.I) for p, _ in SINK_PATTERNS]

    paths = [f["path"] for f in (index.get("files") or [])[:limit_files]]
    texts: dict[str, str] = {}
    for rel in paths:
        text = _read(workdir, rel)
        if not text:
            continue
        texts[rel] = text
        tags: set[str] = set()
        if any(rx.search(text) for rx in src_rx):
            tags.add("source")
        if any(rx.search(text) for rx in sink_rx):
            tags.add("sink")
        file_tags[rel] = tags
        for rx in (DEF_RX, ASSIGN_FN_RX):
            for m in rx.finditer(text):
                name = m.group(1)
                line = text[: m.start()].count("\n") + 1
                functions.append({"name": name, "path": rel, "line": line})
                by_name.setdefault(name, []).append(rel)

    calls: list[dict[str, str]] = []
    for rel, text in texts.items():
        defined = {f["name"] for f in functions if f["path"] == rel}
        for m in CALL_RX.finditer(text):
            name = m.group(1)
            if name in SKIP_CALLS or name in defined:
                continue
            targets = by_name.get(name)
            if not targets:
                continue
            for dest in targets[:3]:
                if dest == rel:
                    continue
                calls.append({"from": rel, "to": dest, "symbol": name})
                if len(calls) >= 200:
                    break
            if len(calls) >= 200:
                break

    taint: list[str] = []
    for rel, tags in file_tags.items():
        if "source" in tags and "sink" in tags:
            taint.append(f"{rel} contains both attacker input and a sink")
    for edge in calls:
        src_tags = file_tags.get(edge["from"], set())
        dst_tags = file_tags.get(edge["to"], set())
        if "source" in src_tags and "sink" in dst_tags:
            taint.append(
                f"{edge['from']} (source) calls {edge['symbol']}() in {edge['to']} (sink)"
            )
        if len(taint) >= 40:
            break

    return {
        "functions": functions[:250],
        "calls": calls[:200],
        "taint": taint[:40],
        "source_files": sorted(p for p, t in file_tags.items() if "source" in t),
        "sink_files": sorted(p for p, t in file_tags.items() if "sink" in t),
    }


def git_changed_files(workdir: Path, base_ref: str | None = None) -> dict[str, Any]:
    workdir = workdir.resolve()
    if not (workdir / ".git").exists():
        return {"available": False, "base": None, "files": []}
    bases = [b for b in [base_ref, "origin/main", "main", "master", "HEAD~1"] if b]
    last_err = ""
    for base in bases:
        try:
            out = subprocess.run(
                ["git", "-C", str(workdir), "diff", "--name-only", "-z", base],
                check=True,
                capture_output=True,
                text=True,
            )
            files = [p for p in out.stdout.split("\0") if p]
            return {"available": True, "base": base, "files": files[:200]}
        except (OSError, subprocess.CalledProcessError) as exc:
            last_err = str(exc)
            continue
    return {"available": False, "base": None, "files": [], "error": last_err[:200]}
