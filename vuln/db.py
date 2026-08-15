from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from .config import DB_PATH, ensure_dirs

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    workdir TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    focus TEXT NOT NULL DEFAULT '',
    agent_ids TEXT NOT NULL,
    index_json TEXT,
    threat_model TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    cwe TEXT,
    summary TEXT NOT NULL,
    description TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,
    attack_path TEXT NOT NULL,
    evidence TEXT NOT NULL,
    confidence REAL NOT NULL,
    verified INTEGER NOT NULL,
    agent TEXT NOT NULL,
    status TEXT NOT NULL,
    chain_id TEXT,
    created_at TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    agent TEXT,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    payload TEXT,
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    phase TEXT NOT NULL,
    description TEXT NOT NULL,
    focus TEXT NOT NULL,
    builtin INTEGER NOT NULL,
    enabled INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chains (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    steps TEXT NOT NULL,
    finding_ids TEXT NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);
"""


def connect() -> sqlite3.Connection:
    ensure_dirs()
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    if "details" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN details TEXT")
    conn.commit()


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def loads(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    return json.loads(value)
