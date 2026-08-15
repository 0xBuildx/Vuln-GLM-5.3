from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(os.getenv("VULN_DATA_DIR", ROOT / "data"))
REPOS_DIR = DATA_DIR / "repos"
DB_PATH = DATA_DIR / "vuln.db"
WEB_DIR = ROOT / "web"
FIXTURE_DIR = ROOT / "fixtures" / "harbor-shop"

HOST = os.getenv("VULN_HOST", "127.0.0.1")
PORT = int(os.getenv("VULN_PORT", "4173"))

# GLM-5.3 (Z.ai) is the default live engine — cybersecurity / exploit-chain post-training.
ZAI_API_KEY = os.getenv("ZAI_API_KEY", "").strip()
ZAI_BASE_URL = os.getenv("ZAI_BASE_URL", "https://api.z.ai/api/coding/paas/v4").rstrip("/")
ZAI_MODEL = os.getenv("ZAI_MODEL", "glm-5.3")

# Optional SpaceXAI / xAI fallback
XAI_API_KEY = os.getenv("XAI_API_KEY", "").strip()
XAI_BASE_URL = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1").rstrip("/")
XAI_MODEL = os.getenv("XAI_MODEL", "grok-4.6")

_runtime_keys: dict[str, str] = {"zai": "", "xai": ""}
_runtime_provider: str | None = None

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".jj",
    ".venv",
    "venv",
    "virtualenv",
    "node_modules",
    "bower_components",
    "jspm_packages",
    ".pnpm-store",
    ".yarn",
    "dist",
    "build",
    "out",
    "output",
    ".output",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    ".cache",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    ".nyc_output",
    "coverage",
    "vendor",
    "Pods",
    ".gradle",
    ".idea",
    ".vscode",
    "site-packages",
    "data",
}

# Dot-directories we still want to read (CI / secrets often live here).
KEEP_DOT_DIRS = {".github", ".gitlab", ".circleci"}

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mov",
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".pyc",
    ".so",
    ".dylib",
    ".bin",
}

MAX_FILE_BYTES = 200_000
MAX_INDEX_FILES = 450
MAX_PROMPT_CHARS = 160_000
FULL_DUMP_CHARS = 180_000
HUNT_ROUNDS = int(os.getenv("VULN_HUNT_ROUNDS", "12"))
# Max simultaneous GLM hunts (API concurrency). GLM-5.3 coding plan is ~5.
HUNT_CONCURRENCY = max(1, int(os.getenv("VULN_CONCURRENCY", "5")))
HUNT_WORKERS = int(os.getenv("VULN_WORKERS", str(HUNT_CONCURRENCY)))

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".sol": "solidity",
    ".tf": "terraform",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".sql": "sql",
    ".sh": "shell",
    ".ex": "elixir",
    ".exs": "elixir",
    ".vue": "vue",
    ".svelte": "svelte",
}


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPOS_DIR.mkdir(parents=True, exist_ok=True)


def set_runtime_key(provider: str, key: str) -> None:
    if provider not in _runtime_keys:
        raise ValueError("provider must be zai or xai")
    _runtime_keys[provider] = key.strip()


def set_runtime_provider(provider: str | None) -> None:
    global _runtime_provider
    if provider is not None and provider not in {"auto", "zai", "xai"}:
        raise ValueError("provider must be auto, zai, or xai")
    _runtime_provider = None if provider in {None, "auto"} else provider


def zai_key() -> str:
    return _runtime_keys["zai"] or ZAI_API_KEY


def xai_key() -> str:
    return _runtime_keys["xai"] or XAI_API_KEY


def active_provider() -> str | None:
    if _runtime_provider == "zai" and zai_key():
        return "zai"
    if _runtime_provider == "xai" and xai_key():
        return "xai"
    if zai_key():
        return "zai"
    if xai_key():
        return "xai"
    return None


def live_ready() -> bool:
    return active_provider() is not None


def active_model() -> str:
    return ZAI_MODEL if active_provider() == "zai" else XAI_MODEL


def active_base_url() -> str:
    return ZAI_BASE_URL if active_provider() == "zai" else XAI_BASE_URL


def active_api_key() -> str:
    return zai_key() if active_provider() == "zai" else xai_key()
