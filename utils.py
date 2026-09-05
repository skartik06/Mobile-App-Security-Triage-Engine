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
# CVSS-Style Severity Scoring Engine
# ---------------------------------------------------------------------------

# Base scores per finding type (0.0 – 10.0 scale, inspired by CVSS v3)
_BASE_SCORES: dict[str, float] = {
    # Permissions — score reflects sensitivity of data/capability exposed
    "dangerous_permission": 5.0,

    # Exported components — directly exploitable by other apps
    "exported_activity":  8.0,
    "exported_service":   9.0,
    "exported_receiver":  7.5,
    "exported_provider":  8.5,
    "exported_component": 8.0,   # generic fallback

    # Secrets — depends on what's hardcoded (modifier applied below)
    "hardcoded_secret": 6.5,

    # Cryptography weaknesses
    "weak_crypto": 6.0,

    # Network / cleartext
    "cleartext_traffic":       7.5,
    "low_target_sdk_cleartext": 6.0,
}

# Per-permission severity modifiers
_PERMISSION_SCORES: dict[str, float] = {
    "READ_SMS":                 9.0,
    "SEND_SMS":                 8.5,
    "RECEIVE_SMS":              8.5,
    "PROCESS_OUTGOING_CALLS":   8.0,
    "READ_CALL_LOG":            8.0,
    "RECORD_AUDIO":             8.0,
    "CAMERA":                   7.5,
    "ACCESS_FINE_LOCATION":     7.5,
    "READ_CONTACTS":            7.0,
    "GET_ACCOUNTS":             7.0,
    "READ_PHONE_STATE":         6.5,
    "WRITE_EXTERNAL_STORAGE":   6.0,
    "READ_EXTERNAL_STORAGE":    5.5,
    "ACCESS_COARSE_LOCATION":   5.5,
    "INTERNET":                 4.0,
    "ACCESS_NETWORK_STATE":     3.5,
    "VIBRATE":                  1.0,
    "RECEIVE_BOOT_COMPLETED":   3.0,
    "WAKE_LOCK":                2.0,
}

# Crypto algorithm scores
_CRYPTO_SCORES: dict[str, float] = {
    "DES":     8.5,
    "RC4":     8.5,
    "RC2":     8.0,
    "MD5":     7.0,
    "SHA-1":   5.5,
    "AES/ECB": 7.5,
}

# Secret pattern scores
_SECRET_SCORES: dict[str, float] = {
    "Private key / certificate":  9.5,
    "AWS Access Key":             9.5,
    "Hardcoded password":         9.0,
    "Hardcoded API key":          8.5,
    "Firebase URL":               7.5,
    "Hardcoded token":            8.0,
    "Hardcoded IP address":       6.0,
    "Hardcoded URL (HTTP)":       4.5,
}


def compute_score(finding_type: str, evidence: str = "", extra: dict | None = None) -> float:
    """Compute a CVSS-inspired numeric risk score (0.0–10.0) for a finding.

    Args:
        finding_type: Machine-readable type slug from make_finding().
        evidence:     Raw evidence string (used for context-aware modifiers).
        extra:        Extra metadata dict (e.g. contains 'permission', 'pattern').

    Returns:
        Float score rounded to 1 decimal place.
    """
    extra = extra or {}
    base = _BASE_SCORES.get(finding_type, 5.0)

    # Permission — use per-permission table if available
    if finding_type == "dangerous_permission":
        perm = extra.get("permission", evidence).split(".")[-1].upper()
        base = _PERMISSION_SCORES.get(perm, base)

    # Crypto — pick algorithm score from evidence
    elif finding_type == "weak_crypto":
        for algo, score in _CRYPTO_SCORES.items():
            if algo.upper() in evidence.upper():
                base = score
                break

    # Secret — use pattern label if available
    elif finding_type == "hardcoded_secret":
        pattern = extra.get("pattern", "")
        for label, score in _SECRET_SCORES.items():
            if label.lower() in pattern.lower():
                base = score
                break

    return round(min(max(base, 0.0), 10.0), 1)


def score_to_severity(score: float) -> str:
    """Map a numeric score to a CVSS severity label.

    Args:
        score: Numeric score 0.0–10.0.

    Returns:
        One of: Critical / High / Medium / Low / Info
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "Info"


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
    """Construct a standardised finding dict with auto-computed risk score.

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
        Dict conforming to the finding schema, including 'cvss_score' and
        computed 'severity' fields.
    """
    score = compute_score(finding_type, evidence, extra)
    severity = score_to_severity(score)

    finding: dict[str, Any] = {
        "id":           make_finding_id(category),
        "type":         finding_type,
        "cvss_score":   score,
        "severity":     severity,          # computed from score
        "severity_hint": severity_hint,    # kept for backward compat
        "title":        title,
        "location":     location,
        "evidence":     evidence,
        "source":       source,
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
