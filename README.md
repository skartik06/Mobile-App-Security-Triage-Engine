# Mobile App Security Triage Engine 🔍

A Python CLI tool that automates static security analysis of Android APK files,
auto-generates Frida dynamic instrumentation hooks, and produces an AI-powered
severity-ranked Markdown report — all from a single command.

> ⚠️ **For defensive security research and portfolio purposes only.**  
> Only analyze apps you own or have **explicit written permission** to test.

---

## Features

| Phase | Tool | What it does |
|-------|------|-------------|
| **Static Analysis** | Androguard + JADX | Decompiles APK; scans for hardcoded secrets, dangerous permissions, exported components, weak crypto (MD5/DES/ECB), cleartext traffic |
| **Hook Generation** | Frida (JS) | Auto-generates Frida hook scripts targeting suspicious methods found in static analysis |
| **AI Report** | LangChain + Claude/GPT-4 | Converts raw JSON findings into a severity-ranked, human-readable Markdown report with exploit paths and remediations |

---

## Project Structure

```
Mobile App Security Triage Engine/
├── triage.py            # CLI entry point
├── static_analysis.py   # Phase 1: APK decompilation + scanning
├── hook_generator.py    # Phase 2: Frida hook script generator
├── ai_summarizer.py     # Phase 3: AI summarization via LangChain
├── utils.py             # Shared helpers (logging, finding schema, JSON I/O)
├── requirements.txt
├── .env.example         # API key template
└── reports/             # Generated output (gitignored)
    ├── AppName_findings.json
    ├── com_example_app_hooks.js
    └── AppName_20240101_120000_report.md
```

---

## Setup

### 1. Prerequisites

- **Python 3.11+**
- **JADX** (optional but recommended for deeper Java source scanning)
  - Download: https://github.com/skylot/jadx/releases
  - Windows: Extract zip, set `JADX_PATH=C:\jadx\bin\jadx.bat` in `.env`
  - Linux/macOS: `brew install jadx` or place binary in PATH
- **Frida** (for running the generated hook scripts on a device):
  ```bash
  pip install frida-tools
  # Also install frida-server on your rooted device / emulator
  ```

### 2. Install Python Dependencies

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
```

### 3. Configure API Keys

```bash
# Copy the template
cp .env.example .env

# Edit .env and fill in your keys
```

`.env` contents:
```env
LLM_PROVIDER=anthropic          # or "openai"
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...           # only needed if LLM_PROVIDER=openai
JADX_PATH=C:\jadx\bin\jadx.bat  # optional
```

---

## Usage

```bash
# Full pipeline (static + hooks + AI report)
python triage.py --apk path/to/app.apk

# Skip AI summarization (faster, no API key needed)
python triage.py --apk path/to/app.apk --skip-ai

# Skip hook generation
python triage.py --apk path/to/app.apk --skip-hooks

# Custom output directory + verbose logging
python triage.py --apk app.apk --output-dir ./my_reports --verbose

# Help
python triage.py --help
```

### Output Files

After a full run, the `reports/` directory will contain:

| File | Description |
|------|-------------|
| `<AppName>_findings.json` | Raw structured findings from static analysis |
| `<package>_hooks.js` | Frida hook script (run manually on device) |
| `<AppName>_YYYYMMDD_HHMMSS_report.md` | AI-generated Markdown security report |

### Running Frida Hooks (Manual)

```bash
# Spawn mode (restarts the app — hooks from the very start)
frida -U -f com.example.app -l reports/com_example_app_hooks.js --no-pause

# Attach mode (attaches to already-running app)
frida -U --attach-name com.example.app -l reports/com_example_app_hooks.js
```

---

## Example: DIVA Android

[DIVA (Damn Insecure and Vulnerable App)](https://github.com/payatu/diva-android)
is a purpose-built vulnerable Android app for testing:

```bash
# Download DIVA APK from GitHub releases, then:
python triage.py --apk DivaApplication.apk --verbose
```

Expected findings include: hardcoded API keys, cleartext HTTP, MD5 crypto,
exported activities, dangerous permissions.

---

## Finding Schema

Each finding in `findings.json` follows this structure:

```json
{
  "id": "CRYPTO_001",
  "type": "weak_crypto",
  "severity_hint": "High",
  "title": "Weak/deprecated crypto: MD5 MessageDigest",
  "location": "com.example.app.Utils.hashPassword()",
  "evidence": "java/security/MessageDigest.getInstance(\"MD5\")",
  "source": "androguard",
  "algorithm": "MD5"
}
```

| Field | Description |
|-------|-------------|
| `id` | Unique finding ID (category + counter) |
| `type` | Machine-readable vulnerability type |
| `severity_hint` | Critical / High / Medium / Low |
| `title` | One-line human-readable description |
| `location` | Class.method() or file where evidence was found |
| `evidence` | Raw code snippet / string that triggered the finding |
| `source` | Tool that found it: `androguard`, `jadx`, or `regex` |

---

## Scan Coverage

| Check | Source |
|-------|--------|
| Dangerous Android permissions | AndroidManifest.xml (Androguard) |
| Custom permissions | AndroidManifest.xml (Androguard) |
| Exported Activities (no permission guard) | Manifest + Intent-filter analysis |
| Exported Services / Receivers / Providers | Manifest analysis |
| Hardcoded secrets (API keys, tokens, passwords) | DEX string pool (Androguard) + Java source (JADX) |
| Weak crypto: MD5, SHA-1 | Dalvik xref analysis (Androguard) |
| Weak crypto: DES, RC4, ECB mode | Dalvik xref analysis (Androguard) |
| Cleartext HTTP (`usesCleartextTraffic`) | AndroidManifest.xml |
| Network Security Config issues | `res/xml/network_security_config.xml` |
| User certificate trust (MITM risk) | Network Security Config XML |
| Low target SDK (< 28, cleartext default) | AndroidManifest.xml |

---

## Roadmap

- [ ] Phase 2: Full Frida hook execution integration (non-MVP)
- [ ] CVSS scoring overlay on findings
- [ ] HTML report output option
- [ ] Integration with MobSF API for extended scanning
- [ ] CI/CD mode: exit code based on severity threshold

---

## Disclaimer

This tool is intended for **defensive security research** on applications
you own or have **explicit written permission** to test.
Unauthorized security testing may violate laws including the
Computer Fraud and Abuse Act (CFAA) and equivalent legislation in your jurisdiction.
