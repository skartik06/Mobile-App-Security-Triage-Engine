"""
utils.py — Shared utilities for the Mobile App Security Triage Engine.

Provides:
- Structured logger with rich coloring
- Finding ID generator
- JSON serialization helpers
- Path validation helpers
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Console / Logging Setup
# ---------------------------------------------------------------------------

_THEME = Theme(
    {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "green",
        "dim": "dim",
    }
)

console = Console(theme=_THEME)


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    """Return a Rich-formatted logger.

    Args:
        name: Logger name (typically __name__).
        verbose: If True, set level to DEBUG; otherwise INFO.

    Returns:
        Configured Logger instance.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )
    return logging.getLogger(name)


# Module-level default logger (verbose off; callers override via get_logger)
logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Finding ID Generator
# ---------------------------------------------------------------------------

_FINDING_COUNTERS: dict[str, int] = {}


def make_finding_id(category: str) -> str:
    """Generate a unique, deterministic finding ID like 'CRYPTO_001'.

    IDs are scoped to the current process run (counters reset on import).

    Args:
        category: Short uppercase category string (e.g. 'CRYPTO', 'PERM').

    Returns:
        ID string, e.g. 'CRYPTO_003'.
    """
    category = category.upper()
    _FINDING_COUNTERS[category] = _FINDING_COUNTERS.get(category, 0) + 1
    return f"{category}_{_FINDING_COUNTERS[category]:03d}"


# ---------------------------------------------------------------------------
# Finding Schema Helper
# ---------------------------------------------------------------------------

def make_finding(
    *,
    category: str,
    finding_type: str,
    severity_hint: str,
    title: str,
    location: str,
    evidence: str,
    line: int | None = None,
    source: str = "androguard",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a standardised finding dict.

    Args:
        category:      Short category for ID prefix (e.g. 'CRYPTO').
        finding_type:  Machine-readable type slug (e.g. 'weak_crypto').
        severity_hint: One of Critical / High / Medium / Low.
        title:         Human-readable one-liner.
        location:      Class.method() or file path where evidence was found.
        evidence:      The raw code snippet or string that triggered the finding.
        line:          Optional source line number.
        source:        Tool that produced this finding ('androguard', 'jadx', 'regex').
        extra:         Any additional metadata to attach.

    Returns:
        Dict conforming to the finding schema.
    """
    finding: dict[str, Any] = {
        "id": make_finding_id(category),
        "type": finding_type,
        "severity_hint": severity_hint,
        "title": title,
        "location": location,
        "evidence": evidence,
        "source": source,
    }
    if line is not None:
        finding["line"] = line
    if extra:
        finding.update(extra)
    return finding


# ---------------------------------------------------------------------------
# JSON Helpers
# ---------------------------------------------------------------------------

def save_json(data: Any, path: Path) -> None:
    """Write *data* to *path* as pretty-printed JSON.

    Parent directories are created automatically.

    Args:
        data: JSON-serializable Python object.
        path: Destination file path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
    logger.debug(f"Saved JSON → {path}")


def load_json(path: Path) -> Any:
    """Load and return JSON from *path*.

    Args:
        path: Source file path.

    Returns:
        Deserialized Python object.

    Raises:
        FileNotFoundError: If path does not exist.
        json.JSONDecodeError: If file content is invalid JSON.
    """
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Path Helpers
# ---------------------------------------------------------------------------

def resolve_apk_path(apk_path: str) -> Path:
    """Validate that *apk_path* points to an existing .apk file.

    Args:
        apk_path: Raw string path from CLI argument.

    Returns:
        Resolved Path object.

    Raises:
        SystemExit: If the path is invalid or not an APK.
    """
    p = Path(apk_path).resolve()
    if not p.exists():
        console.print(f"[critical]✗ APK not found:[/critical] {p}")
        sys.exit(1)
    if p.suffix.lower() != ".apk":
        console.print(f"[high]⚠ File does not have .apk extension:[/high] {p}")
        # Warn but don't abort — some APKs are renamed.
    return p


def make_report_path(output_dir: Path, app_name: str) -> Path:
    """Build the output report file path.

    Args:
        output_dir: Directory to write reports into.
        app_name:   Clean application name (used in filename).

    Returns:
        Path like output_dir/<app_name>_report.md.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return output_dir / f"{app_name}_{timestamp}_report.md"
