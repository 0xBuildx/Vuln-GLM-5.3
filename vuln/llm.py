from __future__ import annotations

import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from openai import OpenAI

from . import config
from .ingest import grep_repo, list_dir, numbered, read_file

_client: OpenAI | None = None
_client_sig: str | None = None


class LLMError(RuntimeError):
    pass


EventFn = Callable[[str, str, Any], None]

HUNT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a repository file with line numbers. Path is relative to the repo root.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "Regex search across the repository. Optional glob like *.py.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "glob": {"type": "string"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files under a relative directory.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_many",
            "description": "Read up to 8 repository files at once. Prefer this over many read_file calls.",
            "parameters": {
                "type": "object",
                "properties": {
                    "paths": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["paths"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "routes",
            "description": "Return extracted HTTP routes and their source files.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_result",
            "description": "Submit the final JSON result for this hunt. Call this once you have evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {"type": "string"},
                    "findings": {"type": "array"},
                    "summary": {"type": "string"},
                    "services": {"type": "array"},
                    "entry_points": {"type": "array"},
                    "auth": {"type": "object"},
                    "sensitive_objects": {"type": "array"},
                    "trust_boundaries": {"type": "array"},
                    "hunt_leads": {"type": "array"},
                    "priority_files": {"type": "array"},
                    "chains": {"type": "array"},
                    "verdicts": {"type": "array"},
                },
            },
        },
    },
]


def client() -> OpenAI:
    global _client, _client_sig
    key = config.active_api_key()
    if not key:
        raise LLMError(
            "No live model key. Add ZAI_API_KEY (GLM-5.3) or XAI_API_KEY to .env, "
            "or paste a key in Settings."
        )
    sig = f"{config.active_provider()}:{key[:8]}:{config.active_base_url()}"
    if _client is None or _client_sig != sig:
        _client = OpenAI(api_key=key, base_url=config.active_base_url())
        _client_sig = sig
    return _client


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _is_rate_limit(exc: BaseException) -> bool:
    text = str(exc).lower()
    code = getattr(exc, "status_code", None)
    if code == 429:
        return True
    return "429" in text or "rate limit" in text or "1302" in text


def _retry_after(exc: BaseException) -> float | None:
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None) or {}
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return max(0.5, float(raw))
    except (TypeError, ValueError):
        return None


def _create(**kwargs: Any) -> Any:
    extra: dict[str, Any] = {}
    if config.active_provider() == "zai":
        extra["thinking"] = {"type": "enabled"}
    last: BaseException | None = None
    tried_plain = False
    for attempt in range(6):
        try:
            if extra:
                return client().chat.completions.create(extra_body=extra, **kwargs)
            return client().chat.completions.create(**kwargs)
        except Exception as exc:
            last = exc
            if extra and not tried_plain and not _is_rate_limit(exc):
                tried_plain = True
                extra = {}
                continue
            if not _is_rate_limit(exc) or attempt == 5:
                raise
            wait = _retry_after(exc)
            if wait is None:
                wait = min(24.0, (1.6**attempt) + random.random())
            time.sleep(wait)
    raise last or LLMError("rate limited")


def complete_json(system: str, user: str, *, temperature: float = 0.15) -> dict[str, Any]:
    try:
        resp = _create(
            model=config.active_model(),
            temperature=temperature,
            max_tokens=8192,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
        data = _extract_json(content)
        if not isinstance(data, dict):
            raise LLMError("Model did not return a JSON object")
        return data
    except LLMError:
        raise
    except Exception as exc:
        if "response_format" in str(exc).lower() or "json" in str(exc).lower():
            resp = _create(
                model=config.active_model(),
                temperature=temperature,
                max_tokens=8192,
                messages=[
                    {"role": "system", "content": system + "\n\nReturn ONLY valid JSON."},
                    {"role": "user", "content": user},
                ],
            )
            content = resp.choices[0].message.content or "{}"
            data = _extract_json(content)
            if not isinstance(data, dict):
                raise LLMError("Model did not return a JSON object") from exc
            return data
        raise LLMError(str(exc)) from exc


def _run_tool(name: str, args: dict[str, Any], workdir: Path, index: dict[str, Any]) -> str:
    if name == "read_file":
        rel = str(args.get("path") or "")
        try:
            body = read_file(workdir, rel)
        except (OSError, ValueError, FileNotFoundError) as exc:
            return f"ERROR: {exc}"
        return f"{rel}\n{numbered(body)}"
    if name == "grep":
        hits = grep_repo(workdir, str(args.get("pattern") or ""), glob=args.get("glob"))
        if not hits:
            return "No matches."
        lines = [f"{h['path']}:{h['line']}: {h['text']}" for h in hits]
        return "\n".join(lines)
    if name == "list_dir":
        return "\n".join(list_dir(index, str(args.get("path") or "."))) or "(empty)"
    if name == "read_many":
        paths = [str(p) for p in (args.get("paths") or [])][:8]
        if not paths:
            return "ERROR: paths required"
        chunks = []
        for rel in paths:
            try:
                body = read_file(workdir, rel)
            except (OSError, ValueError, FileNotFoundError) as exc:
                chunks.append(f"===== {rel} =====\nERROR: {exc}")
                continue
            chunks.append(f"===== {rel} =====\n{numbered(body)}")
        text = "\n\n".join(chunks)
        return text[:40_000]
    if name == "routes":
        rows = index.get("routes") or []
        if not rows:
            return "No routes extracted."
        return "\n".join(
            f"{r.get('method', 'ANY')} {r.get('path')}  ({r.get('file')})" for r in rows[:120]
        )
    return f"ERROR: unknown tool {name}"


def hunt(
    system: str,
    user: str,
    workdir: Path,
    index: dict[str, Any],
    *,
    on_event: EventFn | None = None,
    max_rounds: int | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Multi-turn tool loop so GLM-5.3 can walk the tree, grep, and cite files."""
    rounds = max_rounds or config.HUNT_ROUNDS
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                system
                + "\n\nYou have tools. Use read_many and grep first. Follow every assigned route "
                "into its service layer. Do not invent paths. Empty findings are only allowed if "
                "notes lists each reviewed route and why it is clean. "
                "Call submit_result with every confirmed finding before you stop."
            ),
        },
        {"role": "user", "content": user},
    ]
    submitted: dict[str, Any] | None = None

    for turn in range(rounds):
        if should_stop and should_stop():
            if on_event:
                on_event("note", "Stopped — audit cancelled.", None)
            return submitted or {"findings": [], "notes": "cancelled"}
        if turn == rounds - 1 and submitted is None:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Last turn. Call submit_result NOW with every confirmed finding. "
                        "If a static lead or assigned route is still unreviewed, include it "
                        "or explain it in notes. Do not return empty without that list."
                    ),
                }
            )
        try:
            resp = _create(
                model=config.active_model(),
                temperature=0.2,
                max_tokens=8192,
                messages=messages,
                tools=HUNT_TOOLS,
            )
        except Exception as exc:
            raise LLMError(str(exc)) from exc

        msg = resp.choices[0].message
        reasoning = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
        if reasoning and on_event:
            snippet = str(reasoning).strip().replace("\n", " ")
            if snippet:
                on_event("think", snippet[:280], None)

        payload = msg.model_dump(exclude_none=True)
        messages.append(payload)

        tool_calls = msg.tool_calls or []
        if not tool_calls:
            if msg.content:
                try:
                    data = _extract_json(msg.content)
                    if isinstance(data, dict):
                        return data
                except Exception:
                    if on_event:
                        on_event("note", (msg.content or "")[:240], None)
            break

        work: list[tuple[Any, str, dict[str, Any]]] = []
        for call in tool_calls:
            name = call.function.name
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if name == "submit_result":
                submitted = args if isinstance(args, dict) else {}
                if on_event:
                    n = len(
                        submitted.get("findings")
                        or submitted.get("chains")
                        or submitted.get("verdicts")
                        or []
                    )
                    on_event("note", f"submit_result ({n} items)", None)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": "accepted",
                    }
                )
                continue
            work.append((call, name, args))

        def _one(item: tuple[Any, str, dict[str, Any]]) -> tuple[Any, str, dict[str, Any], str]:
            call, name, args = item
            return call, name, args, _run_tool(name, args, workdir, index)

        if len(work) == 1:
            done = [_one(work[0])]
        elif work:
            with ThreadPoolExecutor(max_workers=len(work)) as pool:
                done = list(pool.map(_one, work))
        else:
            done = []

        for call, name, args, result in done:
            if on_event:
                label = args.get("path") or args.get("pattern") or ""
                on_event("read" if name == "read_file" else "note", f"{name} {label}".strip(), args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": result[:24_000],
                }
            )
        if submitted is not None:
            return submitted

    return submitted or {"findings": [], "notes": "hunt ended without submit_result"}
