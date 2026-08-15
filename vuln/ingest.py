from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from .config import (
    FULL_DUMP_CHARS,
    KEEP_DOT_DIRS,
    LANG_BY_EXT,
    MAX_FILE_BYTES,
    MAX_INDEX_FILES,
    MAX_PROMPT_CHARS,
    REPOS_DIR,
    SKIP_DIRS,
    SKIP_SUFFIXES,
)

LEAD_PATTERNS: list[tuple[str, str]] = [
    (r"alg['\"]?\s*\)?\.?lower\(\)\s*==\s*['\"]none['\"]|alg\s*==\s*['\"]none['\"]|['\"]none['\"].*jwt", "JWT alg=none / unsigned token"),
    (r"unit_price|price\s*=\s*.*(body|json|request|params)|request\.(json|form).*price", "client-controlled price"),
    (r"f[\"'].*(SELECT|INSERT|UPDATE|DELETE)|execute\(\s*f[\"']|execute\([^)]*\+|%\s*\(.*SELECT", "string-built SQL"),
    (r"shell\s*=\s*True|os\.system\(|subprocess\.(call|run|Popen)\(", "command execution sink"),
    (r"yaml\.load\(|pickle\.loads?\(|Marshal\.load|unserialize\(", "unsafe deserialization"),
    (r"Path\([^)]*\)\s*/|os\.path\.join\([^)]*(filename|name|path|user)", "path join with user input"),
    (r"verify\s*=\s*False|CERT_NONE|_create_unverified_context", "TLS verify disabled"),
    (r"setattr\(|for \w+,\s*\w+ in (body|data|payload|request)", "mass assignment loop"),
    (r"requests\.(get|post|put|request)\(\s*(url|target|host|link)", "SSRF-shaped HTTP fetch"),
    (r"(SECRET|HMAC|JWT_SECRET|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{6,}", "hardcoded secret"),
    (r"password\s*==\s*|plaintext|password.*=.*user\.", "plaintext password compare/leak"),
    (r"webhook|stripe.signature|X-Signature", "webhook / callback"),
]

from .surface import COMPLEX_LEADS

LEAD_PATTERNS.extend(COMPLEX_LEADS)

ROUTE_PATTERNS = [
    re.compile(
        r"""@(?:app|router|api)\.(get|post|put|patch|delete|options|head)\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""(?:app|router|server)\.(get|post|put|patch|delete|options|head)\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""(?:Route|app\.(?:MapGet|MapPost|MapPut|MapDelete))\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(r"""(?:path|re_path)\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(
        r"""(?:get|post|put|patch|delete)\s+['"](/[^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""\(\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*['"]([^'"]+)['"]\s*\)""",
        re.I,
    ),
]

AUTH_HINTS = re.compile(
    r"\b(auth|authorize|authorization|permission|rbac|acl|jwt|session|csrf|oauth|password|api[_-]?key|bearer|can\(|policy|guard)\b",
    re.I,
)
SENSITIVE_HINTS = re.compile(
    r"\b(order|invoice|payment|checkout|wallet|balance|transfer|admin|tenant|org|user_id|account|upload|download|secret|token|ssrf|webhook)\b",
    re.I,
)


def resolve_source(source: str, audit_id: str) -> tuple[str, Path]:
    raw = source.strip()
    if raw.startswith(("http://", "https://", "git@")):
        dest = REPOS_DIR / audit_id
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", raw, str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
        return "git", dest

    path = Path(raw).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Source path does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"Source is not a directory: {path}")
    return "local", path


def skip_dir_name(name: str) -> bool:
    if name in SKIP_DIRS:
        return True
    if name.startswith(".") and name not in KEEP_DOT_DIRS:
        return True
    return False


def _should_skip(path: Path) -> bool:
    if any(skip_dir_name(part) for part in path.parts):
        return True
    name = path.name
    if name.startswith(".") and name not in {".env.example", ".gitignore", ".env"}:
        if path.suffix not in LANG_BY_EXT:
            return True
    lower = name.lower()
    if any(lower.endswith(suf) for suf in SKIP_SUFFIXES):
        return True
    return False


def walk_source(root: Path) -> tuple[list[Path], list[str]]:
    """Yield project files without descending into node_modules, dist, venvs, etc."""
    root = root.resolve()
    skipped: list[str] = []
    files: list[Path] = []
    if skip_dir_name(root.name):
        return [], [root.name]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep: list[str] = []
        for dirname in dirnames:
            if skip_dir_name(dirname):
                rel = (Path(dirpath) / dirname).relative_to(root).as_posix()
                skipped.append(rel)
            else:
                keep.append(dirname)
        dirnames[:] = keep
        for filename in filenames:
            path = Path(dirpath) / filename
            rel = path.relative_to(root)
            if _should_skip(rel):
                continue
            files.append(path)
    return files, skipped


def _lang(path: Path) -> str:
    return LANG_BY_EXT.get(path.suffix.lower(), "other")


def _extract_routes(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for pat in ROUTE_PATTERNS:
        for m in pat.finditer(text):
            groups = [g for g in m.groups() if g]
            if len(groups) == 2:
                found.append({"method": groups[0].upper(), "path": groups[1]})
            elif len(groups) == 1:
                found.append({"method": "ANY", "path": groups[0]})
    return found


def _score_file(rel: str, text: str) -> int:
    score = 0
    lowered = rel.lower()
    for token in (
        "auth",
        "session",
        "permission",
        "policy",
        "middleware",
        "route",
        "controller",
        "handler",
        "api",
        "order",
        "payment",
        "billing",
        "checkout",
        "user",
        "admin",
        "upload",
        "jwt",
        "webhook",
        "tenant",
        "guard",
    ):
        if token in lowered:
            score += 8
    score += min(20, len(AUTH_HINTS.findall(text)))
    score += min(16, len(SENSITIVE_HINTS.findall(text)))
    if rel.endswith((".md", ".txt")):
        score -= 4
    return score


def index_repo(
    workdir: Path,
    name: str | None = None,
    on_progress: Any | None = None,
) -> dict[str, Any]:
    workdir = workdir.resolve()
    files: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    languages: Counter[str] = Counter()
    tree_paths: list[str] = []

    def _tick(rel: str, extra: dict[str, Any] | None = None) -> None:
        if not on_progress:
            return
        payload = {
            "files": len(files),
            "seen": len(tree_paths),
            "routes": len(routes),
            "path": rel,
            "languages": dict(languages),
            "skipped": skipped[:20],
        }
        if extra:
            payload.update(extra)
        on_progress(payload)

    source_files, skipped = walk_source(workdir)
    for path in source_files:
        if not path.is_file():
            continue
        rel = path.relative_to(workdir).as_posix()
        tree_paths.append(rel)
        if len(files) >= MAX_INDEX_FILES:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:2048]:
            continue
        if len(data) > MAX_FILE_BYTES:
            text = data[:MAX_FILE_BYTES].decode("utf-8", errors="replace") + "\n… [truncated]"
        else:
            text = data.decode("utf-8", errors="replace")
        lang = _lang(path)
        languages[lang] += 1
        file_routes = _extract_routes(text)
        for route in file_routes:
            routes.append({**route, "file": rel})
        files.append(
            {
                "path": rel,
                "lang": lang,
                "bytes": len(data),
                "sha": hashlib.sha256(data).hexdigest()[:12],
                "score": _score_file(rel, text),
                "auth_hits": len(AUTH_HINTS.findall(text)),
                "sensitive_hits": len(SENSITIVE_HINTS.findall(text)),
                "preview": "\n".join(text.splitlines()[:8]),
            }
        )
        if on_progress and (len(files) == 1 or len(files) % 3 == 0 or file_routes):
            _tick(rel)

    _tick(tree_paths[-1] if tree_paths else "", {"done": True, "skipped": skipped[:40]})
    files.sort(key=lambda f: (-f["score"], f["path"]))
    return {
        "name": name or workdir.name,
        "root": str(workdir),
        "file_count": len(tree_paths),
        "indexed": len(files),
        "languages": dict(languages.most_common()),
        "routes": routes[:200],
        "tree": tree_paths[:2000],
        "files": files,
        "skipped_dirs": skipped[:80],
    }


def read_file(workdir: Path, rel: str) -> str:
    target = (workdir / rel).resolve()
    if not str(target).startswith(str(workdir.resolve())):
        raise ValueError("Path escapes workdir")
    if not target.is_file():
        raise FileNotFoundError(rel)
    data = target.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace") + "\n… [truncated]"
    return data.decode("utf-8", errors="replace")


def numbered(text: str, start: int = 1) -> str:
    lines = text.splitlines()
    width = len(str(start + len(lines)))
    return "\n".join(f"{i:>{width}}| {line}" for i, line in enumerate(lines, start))


def slice_around(text: str, needle: str, radius: int = 12) -> tuple[int, int, str] | None:
    lines = text.splitlines()
    hit = None
    for i, line in enumerate(lines):
        if needle in line:
            hit = i
            break
    if hit is None:
        return None
    start = max(0, hit - radius)
    end = min(len(lines), hit + radius + 1)
    snippet = "\n".join(lines[start:end])
    return start + 1, end, snippet


def pack_files(workdir: Path, index: dict[str, Any], paths: list[str], budget: int) -> str:
    chunks: list[str] = []
    used = 0
    seen: set[str] = set()
    for rel in paths:
        if rel in seen:
            continue
        seen.add(rel)
        try:
            body = read_file(workdir, rel)
        except (OSError, ValueError, FileNotFoundError):
            continue
        block = f"\n===== {rel} =====\n{numbered(body)}\n"
        if used + len(block) > budget:
            remain = budget - used
            if remain > 400:
                chunks.append(block[:remain] + "\n… [budget]")
            break
        chunks.append(block)
        used += len(block)
    return "".join(chunks)


def high_signal_paths(index: dict[str, Any], limit: int = 24) -> list[str]:
    return [f["path"] for f in index.get("files", [])[:limit]]


def entry_paths(index: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for route in index.get("routes") or []:
        if route.get("file"):
            paths.append(route["file"])
    paths.extend(high_signal_paths(index, 40))
    seen: set[str] = set()
    out: list[str] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def pack_attack_surface(workdir: Path, index: dict[str, Any], extra: list[str] | None = None) -> str:
    """Dump the whole tree when it fits; otherwise route files + high-signal + extras."""
    extras = extra or []
    all_src = [
        f["path"]
        for f in index.get("files", [])
        if f.get("lang") not in {None}
    ]
    full = pack_files(workdir, index, all_src, FULL_DUMP_CHARS)
    if full and len(full) < FULL_DUMP_CHARS - 200:
        return full
    return pack_files(
        workdir,
        index,
        list(dict.fromkeys([*extras, *entry_paths(index)])),
        MAX_PROMPT_CHARS,
    )


def static_leads(workdir: Path, index: dict[str, Any], limit: int = 70) -> list[str]:
    leads: list[str] = []
    for pattern, label in LEAD_PATTERNS:
        for hit in grep_repo(workdir, pattern, limit=6):
            if not hit.get("path"):
                continue
            leads.append(f"{hit['path']}:{hit['line']} — {label}: {hit['text'].strip()[:160]}")
            if len(leads) >= limit:
                return leads
    # Dead auth helpers: defined once, never called.
    for helper in ("require_admin", "require_role", "check_permission", "authorize"):
        hits = grep_repo(workdir, rf"\b{helper}\b", limit=12)
        defs = [h for h in hits if re.search(rf"def {helper}\b", h.get("text") or "")]
        if defs and len(hits) <= len(defs) + 1:
            d = defs[0]
            leads.append(f"{d['path']}:{d['line']} — {helper} is defined and almost never called")
    return leads[:limit]


def grep_repo(workdir: Path, pattern: str, glob: str | None = None, limit: int = 80) -> list[dict[str, Any]]:
    try:
        rx = re.compile(pattern, re.I)
    except re.error as exc:
        return [{"path": "", "line": 0, "text": f"invalid regex: {exc}"}]
    hits: list[dict[str, Any]] = []
    suffix = None
    if glob and glob.startswith("*."):
        suffix = glob[1:]
    source_files, _skipped = walk_source(workdir)
    for path in source_files:
        if suffix and not path.name.endswith(suffix):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(workdir).as_posix()
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append({"path": rel, "line": i, "text": line[:240]})
                if len(hits) >= limit:
                    return hits
    return hits


def list_dir(index: dict[str, Any], rel: str) -> list[str]:
    prefix = "" if rel in {".", "", "/"} else rel.strip("/") + "/"
    out: list[str] = []
    seen: set[str] = set()
    for path in index.get("tree") or []:
        if prefix and not path.startswith(prefix):
            continue
        rest = path[len(prefix) :] if prefix else path
        head = rest.split("/", 1)[0]
        if not head or head in seen:
            continue
        seen.add(head)
        out.append(prefix + head + ("/" if "/" in rest else ""))
        if len(out) >= 80:
            break
    return out


def locate(workdir: Path, rel: str, contains: str, radius: int = 10) -> dict[str, Any] | None:
    try:
        text = read_file(workdir, rel)
    except (OSError, ValueError, FileNotFoundError):
        return None
    found = slice_around(text, contains, radius=radius)
    if not found:
        return None
    start, end, snippet = found
    return {
        "path": rel,
        "start_line": start,
        "end_line": end,
        "snippet": snippet,
    }
