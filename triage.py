"""
triage.py — CLI Entry Point for the Mobile App Security Triage Engine.

Usage:
    python triage.py --apk path/to/app.apk
    python triage.py --apk path/to/app.apk --skip-ai --verbose
    python triage.py --apk path/to/app.apk --output-dir ./reports --skip-hooks

Pipeline:
    1. Static Analysis  → structured JSON findings
    2. Hook Generation  → Frida .js script (optional)
    3. AI Summarization → severity-ranked Markdown report (optional)
"""

from __future__ import annotations

import sys
import os

# Force UTF-8 output on Windows so Rich/emoji don't crash on cp1252 terminals.
# This makes `set PYTHONUTF8=1` unnecessary.
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONUTF8", "1")

from pathlib import Path

import click
from dotenv import load_dotenv

# Silence Androguard's very verbose internal loggers.
# Androguard 4.x uses loguru — disable it before any androguard import.
import logging
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass
# Also suppress via stdlib just in case
for _ag_log in ["androguard", "androguard.core.axml", "androguard.core.apk",
                 "androguard.core.dex", "androguard.misc"]:
    logging.getLogger(_ag_log).setLevel(logging.ERROR)

# Load .env before anything else so modules can read env vars on import
load_dotenv()

from utils import console, get_logger, make_report_path, resolve_apk_path, save_json

logger = get_logger(__name__)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--apk", "-a",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Path to the Android APK file to analyze.",
)
@click.option(
    "--output-dir", "-o",
    default="reports",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Directory to write reports and hook scripts into.",
)
@click.option(
    "--skip-ai",
    is_flag=True,
    default=False,
    help="Skip the AI summarization step (produces findings JSON + fallback report only).",
)
@click.option(
    "--skip-hooks",
    is_flag=True,
    default=False,
    help="Skip Frida hook script generation.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose/debug logging.",
)
@click.version_option("0.1.0", prog_name="Mobile App Security Triage Engine")
def cli(
    apk: str,
    output_dir: str,
    skip_ai: bool,
    skip_hooks: bool,
    verbose: bool,
) -> None:
    """Mobile App Security Triage Engine — automated Android APK security analysis.

    \b
    Runs a three-phase pipeline:
      1. Static analysis  (Androguard + optional JADX)
      2. Frida hook generation (based on findings)
      3. AI summarization  (Claude or GPT-4 via LangChain)

    \b
    Example:
      python triage.py --apk InsecureBankV2.apk
      python triage.py --apk app.apk --skip-ai --verbose
    """
    # Update logger verbosity after flag is parsed
    global logger
    logger = get_logger(__name__, verbose=verbose)

    apk_path = resolve_apk_path(apk)
    output_path = Path(output_dir).resolve()

    console.print(
        f"\n[bold blue]Mobile App Security Triage Engine[/bold blue]  "
        f"[dim]v0.1.0[/dim]\n"
        f"  APK: [bold]{apk_path.name}[/bold]\n"
        f"  Output dir: {output_path}\n"
    )

    # ---------------------------------------------------------------
    # Phase 1 — Static Analysis
    # ---------------------------------------------------------------
    from static_analysis import APKAnalyzer

    analyzer = APKAnalyzer(apk_path=apk_path, verbose=verbose)
    results = analyzer.run_full_analysis()

    import re
    raw_name = results["app_info"].get("app_name", apk_path.stem) or apk_path.stem
    # Strip non-printable / path-unsafe characters (e.g. garbled AXML output)
    app_name = re.sub(r"[^\w\-]", "_", raw_name).strip("_") or apk_path.stem

    # Save raw findings JSON
    findings_json_path = output_path / f"{app_name}_findings.json"
    save_json(results, findings_json_path)
    console.print(f"[info]✔ Findings JSON saved:[/info] {findings_json_path}")

    # ---------------------------------------------------------------
    # Phase 2 — Frida Hook Generation
    # ---------------------------------------------------------------
    if not skip_hooks:
        from hook_generator import HookGenerator

        generator = HookGenerator(
            findings=results["findings"],
            app_package=results["app_info"].get("package_name", "unknown.package"),
            verbose=verbose,
        )
        hook_script_path = generator.generate(output_dir=output_path)
        console.print(f"[info]✔ Hook script saved:[/info] {hook_script_path}")
    else:
        console.print("[dim]  Skipping Frida hook generation (--skip-hooks).[/dim]")

    # ---------------------------------------------------------------
    # Phase 3 — AI Summarization
    # ---------------------------------------------------------------
    if not skip_ai:
        from ai_summarizer import AISummarizer

        summarizer = AISummarizer(results=results, verbose=verbose)
        markdown_report = summarizer.generate_report()
    else:
        console.print("[dim]  Skipping AI summarization (--skip-ai).[/dim]")
        # Generate fallback report anyway so there's always a .md output
        from ai_summarizer import AISummarizer
        summarizer = AISummarizer(results=results, verbose=verbose)
        markdown_report = summarizer._fallback_report()

    # Save Markdown report
    report_path = make_report_path(output_path, app_name)
    report_path.write_text(markdown_report, encoding="utf-8")
    console.print(f"\n[info]✔ Report saved:[/info] {report_path}")

    # ---------------------------------------------------------------
    # Final Summary
    # ---------------------------------------------------------------
    stats = results.get("stats", {})
    console.print(
        f"\n[bold]Pipeline complete![/bold]  "
        f"[critical]Critical: {stats.get('Critical', 0)}[/critical]  "
        f"[high]High: {stats.get('High', 0)}[/high]  "
        f"[medium]Medium: {stats.get('Medium', 0)}[/medium]  "
        f"[low]Low: {stats.get('Low', 0)}[/low]\n"
    )


if __name__ == "__main__":
    cli()
