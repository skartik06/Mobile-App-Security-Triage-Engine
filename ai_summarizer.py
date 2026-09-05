"""
ai_summarizer.py — Phase 3: AI-Powered Report Summarization.

Uses LangChain + a configurable LLM (Claude or GPT-4) to transform raw JSON
findings from static_analysis.py into a human-readable, severity-ranked
Markdown security report.

The LLM receives:
  1. App metadata (package, version, SDK)
  2. The full findings list in JSON
  3. A structured prompt asking for: severity ranking, plain-English
     explanation per finding, and a suggested exploit path or real-world
     risk scenario.

Usage (programmatic):
    summarizer = AISummarizer(results, verbose=True)
    markdown_report = summarizer.generate_report()

Usage (CLI):
    Called from triage.py — do not run this file directly.

Environment variables:
    LLM_PROVIDER      = "gemini" | "anthropic" | "openai"  (default: gemini)
    GOOGLE_API_KEY    = AIzaSy...               (free — aistudio.google.com)
    GEMINI_MODEL      = gemini-1.5-flash         (default, free tier)
    ANTHROPIC_API_KEY = sk-ant-...
    ANTHROPIC_MODEL   = claude-sonnet-4-5        (default)
    OPENAI_API_KEY    = sk-...
    OPENAI_MODEL      = gpt-4o                   (default)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from utils import console, get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# LangChain imports — graceful failure with helpful error message
# ---------------------------------------------------------------------------

try:
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.language_models.chat_models import BaseChatModel
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert Android mobile security researcher. You will receive a JSON
report produced by a static analysis tool that scanned an Android APK file.

Your task is to produce a clear, actionable Markdown security report with:
1. An executive summary (2–3 sentences).
2. A severity-ranked vulnerability table.
3. For EACH finding: a plain-English explanation of what the vulnerability is,
   why it matters, a concrete real-world risk scenario or exploit path,
   and a specific remediation recommendation.

Format rules:
- Use Markdown headings, bullet points, and code blocks.
- Severity labels: Critical, High, Medium, Low.
- Be specific — reference the exact class names, method names, and evidence
  strings from the findings.
- Do NOT hallucinate findings that are not in the JSON input.
- Keep the tone professional and suitable for a security report reviewed by
  both developers and security leads.
"""

_HUMAN_PROMPT_TEMPLATE = """\
## App Under Analysis

- **Package**: {package_name}
- **App Name**: {app_name}
- **Version**: {version_name} (code {version_code})
- **Min SDK**: {min_sdk} | **Target SDK**: {target_sdk}
- **APK Size**: {file_size_kb} KB

## Raw Static Analysis Findings (JSON)

```json
{findings_json}
```

## Stats

| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High     | {high} |
| Medium   | {medium} |
| Low      | {low} |
| **Total**| **{total}** |

Please generate the full security report now.
"""


class AISummarizer:
    """Generates a Markdown security report from static analysis results using an LLM.

    Attributes:
        results:   Output dict from APKAnalyzer.run_full_analysis().
        provider:  LLM provider: "anthropic" or "openai".
        verbose:   Enable debug logging.
    """

    def __init__(
        self,
        results: dict[str, Any],
        provider: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.results = results
        self.provider = (
            provider
            or os.environ.get("LLM_PROVIDER", "gemini")
        ).lower()
        self.verbose = verbose
        self._llm: "BaseChatModel | None" = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        """Call the LLM and return the Markdown report string.

        Returns:
            Markdown-formatted report as a string.

        Raises:
            SystemExit: If LangChain is not installed or API key is missing.
        """
        if not LANGCHAIN_AVAILABLE:
            console.print(
                "[high]⚠ LangChain is not installed.[/high] "
                "Run: [bold]pip install langchain langchain-anthropic langchain-openai[/bold]"
            )
            return self._fallback_report()

        self._llm = self._build_llm()
        if self._llm is None:
            console.print("[high]⚠ LLM not configured — generating plain-text fallback report.[/high]")
            return self._fallback_report()

        prompt = self._build_prompt()

        console.rule("[bold blue]AI Summarization[/bold blue]")
        console.print(f"[info]▶ Calling {self.provider.capitalize()} LLM…[/info]")

        try:
            messages = [
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
            response = self._llm.invoke(messages)
            # langchain-google-genai may return content as list of parts
            raw = response.content
            if isinstance(raw, list):
                report = "\n".join(
                    p.get("text", str(p)) if isinstance(p, dict) else str(p)
                    for p in raw
                )
            else:
                report = str(raw)
            logger.debug(f"  LLM response length: {len(report)} chars")
            return report
        except Exception as exc:
            console.print(f"[high]⚠ LLM call failed:[/high] {exc}")
            return self._fallback_report()

    # ------------------------------------------------------------------
    # Internal: LLM Construction
    # ------------------------------------------------------------------

    def _build_llm(self) -> "BaseChatModel | None":
        """Instantiate the appropriate LangChain LLM based on LLM_PROVIDER.

        Returns:
            Configured BaseChatModel instance, or None if setup fails.
        """
        if self.provider == "gemini":
            api_key = os.environ.get("GOOGLE_API_KEY", "")
            model   = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
            if not api_key or api_key.startswith("AIzaSy..."):
                console.print(
                    "[high]⚠ GOOGLE_API_KEY not set.[/high] "
                    "Get a free key at: [bold]https://aistudio.google.com/apikey[/bold]"
                )
                return None
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
                return ChatGoogleGenerativeAI(
                    model=model,
                    google_api_key=api_key,
                    temperature=0.2,
                    max_output_tokens=4096,
                )
            except ImportError:
                console.print(
                    "[high]⚠ langchain-google-genai not installed.[/high] "
                    "Run: [bold]pip install langchain-google-genai google-generativeai[/bold]"
                )
                return None

        elif self.provider == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
            if not api_key or api_key.startswith("sk-ant-..."):
                console.print(
                    "[high]⚠ ANTHROPIC_API_KEY not set.[/high] "
                    "Add it to your .env file."
                )
                return None
            try:
                from langchain_anthropic import ChatAnthropic
                return ChatAnthropic(
                    model=model,
                    api_key=api_key,
                    max_tokens=4096,
                    temperature=0.2,  # Low temp = more factual, less creative
                )
            except ImportError:
                console.print(
                    "[high]⚠ langchain-anthropic not installed.[/high] "
                    "Run: [bold]pip install langchain-anthropic[/bold]"
                )
                return None

        elif self.provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
            model = os.environ.get("OPENAI_MODEL", "gpt-4o")
            if not api_key or api_key.startswith("sk-..."):
                console.print(
                    "[high]⚠ OPENAI_API_KEY not set.[/high] "
                    "Add it to your .env file."
                )
                return None
            try:
                from langchain_openai import ChatOpenAI
                return ChatOpenAI(
                    model=model,
                    api_key=api_key,
                    max_tokens=4096,
                    temperature=0.2,
                )
            except ImportError:
                console.print(
                    "[high]⚠ langchain-openai not installed.[/high] "
                    "Run: [bold]pip install langchain-openai[/bold]"
                )
                return None

        else:
            console.print(
                f"[high]⚠ Unknown LLM_PROVIDER: '{self.provider}'.[/high] "
                "Choose 'anthropic' or 'openai'."
            )
            return None

    # ------------------------------------------------------------------
    # Internal: Prompt Construction
    # ------------------------------------------------------------------

    def _build_prompt(self) -> str:
        """Construct the human-turn prompt from analysis results.

        Returns:
            Formatted prompt string.
        """
        app_info = self.results.get("app_info", {})
        findings = self.results.get("findings", [])
        stats = self.results.get("stats", {})

        # Truncate findings list if very large (> 50 findings) to stay within context
        MAX_FINDINGS = 50
        if len(findings) > MAX_FINDINGS:
            logger.warning(
                f"  Truncating findings to {MAX_FINDINGS} (from {len(findings)}) for LLM prompt."
            )
            # Prioritise by severity
            priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            findings = sorted(
                findings,
                key=lambda f: priority.get(f.get("severity_hint", "Low"), 3),
            )[:MAX_FINDINGS]

        findings_json = json.dumps(findings, indent=2, ensure_ascii=False, default=str)

        return _HUMAN_PROMPT_TEMPLATE.format(
            package_name=app_info.get("package_name", "unknown"),
            app_name=app_info.get("app_name", "unknown"),
            version_name=app_info.get("version_name", "?"),
            version_code=app_info.get("version_code", "?"),
            min_sdk=app_info.get("min_sdk", "?"),
            target_sdk=app_info.get("target_sdk", "?"),
            file_size_kb=app_info.get("file_size_kb", "?"),
            findings_json=findings_json,
            critical=stats.get("Critical", 0),
            high=stats.get("High", 0),
            medium=stats.get("Medium", 0),
            low=stats.get("Low", 0),
            total=stats.get("Total", 0),
        )

    # ------------------------------------------------------------------
    # Fallback: Plain-text report without LLM
    # ------------------------------------------------------------------

    def _fallback_report(self) -> str:
        """Generate a minimal Markdown report directly from findings (no LLM).

        Used when the LLM is unavailable or the API key is not configured.

        Returns:
            Plain Markdown report string.
        """
        app_info = self.results.get("app_info", {})
        findings = self.results.get("findings", [])
        stats = self.results.get("stats", {})

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity_hint", "Low"), 3),
        )

        lines: list[str] = [
            f"# Security Report: {app_info.get('app_name', 'Unknown App')}",
            "",
            f"> **Package**: `{app_info.get('package_name', 'unknown')}`  ",
            f"> **Version**: {app_info.get('version_name', '?')} (code {app_info.get('version_code', '?')})  ",
            f"> **Target SDK**: {app_info.get('target_sdk', '?')}",
            "",
            "> ⚠️ _This report was generated without AI summarization._  ",
            "> _Set your API key in .env and re-run with `--ai` for full explanations._",
            "",
            "## Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {stats.get('Critical', 0)} |",
            f"| 🟠 High | {stats.get('High', 0)} |",
            f"| 🟡 Medium | {stats.get('Medium', 0)} |",
            f"| 🟢 Low | {stats.get('Low', 0)} |",
            f"| **Total** | **{stats.get('Total', 0)}** |",
            "",
            "## Findings",
            "",
        ]

        for f in sorted_findings:
            sev = f.get("severity_hint", "Low")
            emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
            lines.append(f"### {emoji} [{f.get('id')}] {f.get('title')}")
            lines.append("")
            lines.append(f"- **Severity**: {sev}")
            lines.append(f"- **Type**: `{f.get('type')}`")
            lines.append(f"- **Location**: `{f.get('location')}`")
            lines.append(f"- **Source**: {f.get('source')}")
            lines.append(f"- **Evidence**:")
            lines.append(f"  ```")
            lines.append(f"  {f.get('evidence', '')}")
            lines.append(f"  ```")
            if f.get("note"):
                lines.append(f"- **Note**: {f['note']}")
            lines.append("")

        return "\n".join(lines)
