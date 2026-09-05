"""
static_analysis.py — Phase 1: APK Static Analysis Module.

Orchestrates APK decompilation and vulnerability scanning using Androguard
(primary) and JADX (optional, for richer Java source analysis).

Usage (programmatic):
    analyzer = APKAnalyzer("path/to/app.apk")
    results  = analyzer.run_full_analysis()
    # results is a dict with keys: "app_info", "findings", "stats"

Usage (CLI):
    Called from triage.py — do not run this file directly.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Androguard imports — handles both 3.x and 4.x API paths gracefully
# ---------------------------------------------------------------------------
try:
    from androguard.misc import AnalyzeAPK
    try:
        # Androguard 3.x path
        from androguard.core.bytecodes.apk import APK
    except ImportError:
        # Androguard 4.x path
        from androguard.core.apk import APK
    from androguard.core.analysis.analysis import Analysis
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

from utils import console, get_logger, make_finding, save_json

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Dangerous & signature-required Android permissions worth flagging
# ---------------------------------------------------------------------------

#: Permissions that pose real user-privacy or security risk if declared
DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NEARBY_WIFI_DEVICES",
    # Privileged / system
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.INTERNET",           # Low on its own; flag if combined
}

#: Custom-permission prefixes that indicate the app defines its own permissions
CUSTOM_PERMISSION_PREFIXES_TO_SKIP = {"android.", "com.android.", "com.google.android."}

# ---------------------------------------------------------------------------
# Regex patterns for secret / credential scanning
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern_name, regex, severity_hint)
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}",                                      "Critical"),
    ("AWS Secret Key",       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "Critical"),
    ("Google API Key",       r"AIza[0-9A-Za-z\-_]{35}",                               "High"),
    ("Firebase URL",         r"https://[a-z0-9\-]+\.firebaseio\.com",                 "Medium"),
    ("Private Key Header",   r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",    "Critical"),
    ("Generic API Key",      r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "High"),
    ("Generic Secret",       r"(?i)(secret|password|passwd|pwd|token)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "High"),
    ("Bearer Token",         r"(?i)bearer\s+[a-zA-Z0-9\-_]{20,}",                    "High"),
    ("Basic Auth Header",    r"(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{10,}",    "High"),
    ("Slack Token",          r"xox[baprs]-[0-9A-Za-z\-]{10,}",                       "Critical"),
    ("GitHub Token",         r"ghp_[0-9A-Za-z]{36}",                                 "Critical"),
    ("Stripe Key",           r"sk_live_[0-9a-zA-Z]{24}",                             "Critical"),
    ("Twilio SID",           r"AC[0-9a-fA-F]{32}",                                   "High"),
    ("Hardcoded IP Address", r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "Low"),
    ("Hardcoded URL (HTTP)", r"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s'\"]*)?", "Medium"),
]

# ---------------------------------------------------------------------------
# Crypto patterns — method signatures to flag in Dalvik bytecode
# ---------------------------------------------------------------------------

WEAK_CRYPTO_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (display_name, class_pattern, method_pattern, severity_hint)
    ("MD5 MessageDigest",       "Ljava/security/MessageDigest;",  "getInstance",  "High"),
    ("SHA-1 MessageDigest",     "Ljava/security/MessageDigest;",  "getInstance",  "Medium"),
    ("DES Cipher",              "Ljavax/crypto/Cipher;",          "getInstance",  "High"),
    ("DES Key",                 "Ljavax/crypto/spec/DESKeySpec;", "<init>",       "High"),
    ("RC4 Cipher",              "Ljavax/crypto/Cipher;",          "getInstance",  "High"),
    ("ECB Mode Cipher",         "Ljavax/crypto/Cipher;",          "getInstance",  "High"),
    ("Custom Random (insecure)","Ljava/util/Random;",             "<init>",       "Medium"),
]

#: Argument values that indicate which algorithm is actually being used
WEAK_ALGO_STRINGS: set[str] = {"MD5", "SHA-1", "SHA1", "DES", "DESede",
                                "RC4", "ARCFOUR", "ECB", "AES/ECB"}

# ---------------------------------------------------------------------------
# Main Analyzer Class
# ---------------------------------------------------------------------------


class APKAnalyzer:
    """Orchestrates static analysis of an Android APK file.

    Attributes:
        apk_path:   Resolved Path to the APK file.
        jadx_path:  Optional path to the JADX binary.
        verbose:    Enable debug logging.
    """

    def __init__(
        self,
        apk_path: str | Path,
        jadx_path: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.apk_path: Path = Path(apk_path).resolve()
        self.jadx_path: str | None = jadx_path or os.environ.get("JADX_PATH") or None
        self.verbose: bool = verbose

        # Will be populated by _load_apk()
        self._apk: "APK | None" = None
        self._dex = None          # list of DexClass objects
        self._analysis: "Analysis | None" = None

        # Accumulator for all findings across scan methods
        self._findings: list[dict[str, Any]] = []

        if not ANDROGUARD_AVAILABLE:
            console.print(
                "[critical]✗ Androguard is not installed.[/critical] "
                "Run: [bold]pip install androguard[/bold]"
            )
            sys.exit(1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_full_analysis(self) -> dict[str, Any]:
        """Run all static analysis passes and return aggregated results.

        Returns:
            Dict with keys:
                - ``app_info``  – package metadata
                - ``findings``  – list of finding dicts (see utils.make_finding)
                - ``stats``     – summary counts by severity
        """
        console.rule("[bold blue]Static Analysis[/bold blue]")

        # --- 1. Load APK ---
        app_info = self._load_apk()

        # --- 2. Run all scan passes ---
        console.print("\n[info]▶ Scanning permissions…[/info]")
        self._findings.extend(self.analyze_permissions())

        console.print("[info]▶ Scanning exported components…[/info]")
        self._findings.extend(self.analyze_exported_components())

        console.print("[info]▶ Scanning for hardcoded secrets…[/info]")
        self._findings.extend(self.scan_for_secrets())

        console.print("[info]▶ Scanning for weak/deprecated crypto…[/info]")
        self._findings.extend(self.scan_crypto_usage())

        console.print("[info]▶ Scanning cleartext traffic configuration…[/info]")
        self._findings.extend(self.scan_cleartext_traffic())

        # --- 3. Optional JADX-enhanced scan ---
        if self.jadx_path:
            console.print(f"[info]▶ Running JADX decompilation for deeper scan…[/info]")
            jadx_findings = self._run_jadx_and_scan()
            self._findings.extend(jadx_findings)
        else:
            logger.debug("JADX_PATH not set — skipping Java source scan.")

        # --- 4. Compute stats ---
        stats = self._compute_stats(self._findings)

        # --- 5. Print summary ---
        self._print_summary(stats)

        return {
            "app_info": app_info,
            "findings": self._findings,
            "stats": stats,
        }

    # ------------------------------------------------------------------
    # Internal: APK Loading
    # ------------------------------------------------------------------

    def _load_apk(self) -> dict[str, Any]:
        """Parse the APK with Androguard and extract basic app metadata.

        Uses a two-phase approach:
        1. Try ``AnalyzeAPK`` for full DEX + analysis support.
        2. If DEX analysis fails (e.g. minimal/malformed DEX), fall back to
           APK-only mode — permission and manifest scans still work.

        Returns:
            Dict of app metadata (package, version, min SDK, etc.).
        """
        logger.debug(f"Loading APK: {self.apk_path}")

        # Phase 1: Full analysis (APK + DEX + Analysis graph)
        try:
            self._apk, self._dex, self._analysis = AnalyzeAPK(str(self.apk_path))
            logger.debug("AnalyzeAPK succeeded (full mode)")
        except Exception as exc:
            logger.warning(f"AnalyzeAPK full mode failed ({exc}). Trying APK-only fallback…")
            # Phase 2: APK-only (manifest, permissions, components — no DEX)
            try:
                self._apk = APK(str(self.apk_path))
                self._dex = None
                self._analysis = None
                logger.debug("APK-only mode active. DEX-dependent scans will be skipped.")
            except Exception as exc2:
                console.print(f"[critical]✗ Failed to parse APK:[/critical] {exc2}")
                sys.exit(1)

        app_info = {
            "package_name":   self._apk.get_package() or "unknown",
            "app_name":       self._apk.get_app_name() or self.apk_path.stem,
            "version_name":   self._apk.get_androidversion_name() or "?",
            "version_code":   self._apk.get_androidversion_code() or "?",
            "min_sdk":        self._apk.get_min_sdk_version() or "?",
            "target_sdk":     self._apk.get_target_sdk_version() or "?",
            "apk_path":       str(self.apk_path),
            "file_size_kb":   round(self.apk_path.stat().st_size / 1024, 1),
        }

        console.print(
            f"\n[bold]App:[/bold] {app_info['app_name']}  "
            f"[dim]({app_info['package_name']})[/dim]\n"
            f"[bold]Version:[/bold] {app_info['version_name']} "
            f"(code {app_info['version_code']})  "
            f"[bold]Min SDK:[/bold] {app_info['min_sdk']}  "
            f"[bold]Target SDK:[/bold] {app_info['target_sdk']}"
        )
        return app_info

    # ------------------------------------------------------------------
    # Scan Pass 1: Permissions
    # ------------------------------------------------------------------

    def analyze_permissions(self) -> list[dict[str, Any]]:
        """Flag dangerous or over-privileged permissions declared in the manifest.

        Returns:
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []
        declared = self._apk.get_permissions()

        for perm in declared:
            # --- Dangerous known permission ---
            if perm in DANGEROUS_PERMISSIONS:
                # INTERNET alone is Low; combine-check could be added later
                sev = "Low" if perm == "android.permission.INTERNET" else "Medium"
                findings.append(make_finding(
                    category="PERM",
                    finding_type="dangerous_permission",
                    severity_hint=sev,
                    title=f"Dangerous permission declared: {perm.split('.')[-1]}",
                    location="AndroidManifest.xml",
                    evidence=perm,
                    source="androguard",
                ))

            # --- Custom permission (app defines its own) ---
            elif not any(perm.startswith(p) for p in CUSTOM_PERMISSION_PREFIXES_TO_SKIP):
                findings.append(make_finding(
                    category="PERM",
                    finding_type="custom_permission",
                    severity_hint="Low",
                    title=f"Custom permission declared: {perm}",
                    location="AndroidManifest.xml",
                    evidence=perm,
                    source="androguard",
                    extra={"note": "Custom permissions can be exploited if protectionLevel is not signature"},
                ))

        logger.debug(f"  permissions: {len(declared)} declared, {len(findings)} flagged")
        return findings

    # ------------------------------------------------------------------
    # Scan Pass 2: Exported Components
    # ------------------------------------------------------------------

    def analyze_exported_components(self) -> list[dict[str, Any]]:
        """Find Activities, Services, and BroadcastReceivers exported without protection.

        An exported component without ``android:permission`` is accessible to any
        app on the device — a potential target for intent hijacking or data theft.

        Returns:
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []

        # Androguard exposes exported components via the APK object
        component_getters = {
            "Activity":          (self._apk.get_activities,          self._apk.get_intent_filters),
            "Service":           (self._apk.get_services,            lambda n: []),
            "BroadcastReceiver": (self._apk.get_receivers,           lambda n: []),
            "ContentProvider":   (self._apk.get_providers,           lambda n: []),
        }

        for comp_type, (get_components, _) in component_getters.items():
            for component_name in get_components():
                # Check if exported
                exported = self._apk.get_declared_permissions_details().get(component_name)
                # Fallback: check the raw XML attribute
                is_exported = self._is_component_exported(component_name)
                if not is_exported:
                    continue

                # Check if it has a permission guard
                perm_guard = self._get_component_permission(component_name)
                if perm_guard:
                    # Has a permission — lower severity
                    findings.append(make_finding(
                        category="EXPORT",
                        finding_type="exported_component_with_permission",
                        severity_hint="Low",
                        title=f"Exported {comp_type} protected by permission",
                        location=component_name,
                        evidence=f"android:exported=true, android:permission={perm_guard}",
                        source="androguard",
                        extra={"component_type": comp_type, "permission": perm_guard},
                    ))
                else:
                    # No permission guard — higher severity
                    sev = "High" if comp_type in ("Activity", "ContentProvider") else "Medium"
                    findings.append(make_finding(
                        category="EXPORT",
                        finding_type="exported_component_no_permission",
                        severity_hint=sev,
                        title=f"Exported {comp_type} with no permission guard",
                        location=component_name,
                        evidence="android:exported=true, no android:permission attribute",
                        source="androguard",
                        extra={"component_type": comp_type},
                    ))

        logger.debug(f"  exported components: {len(findings)} flagged")
        return findings

    def _is_component_exported(self, component_name: str) -> bool:
        """Check whether a component is exported via manifest XML parsing.

        Args:
            component_name: Fully-qualified component class name.

        Returns:
            True if component is exported (explicit or implicit via intent-filter).
        """
        try:
            # Check explicit exported attribute in AndroidManifest
            xml = self._apk.get_android_manifest_xml()
            if xml is None:
                return False

            # Walk all elements looking for matching name
            for elem in xml.iter():
                name_attr = elem.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                if name_attr == component_name or name_attr == component_name.split(".")[-1]:
                    exported_attr = elem.get(
                        "{http://schemas.android.com/apk/res/android}exported"
                    )
                    if exported_attr == "true":
                        return True
                    if exported_attr == "false":
                        return False
                    # No explicit attribute: exported if has intent-filter
                    has_intent_filter = any(
                        child.tag == "intent-filter" for child in elem
                    )
                    return has_intent_filter
        except Exception as exc:
            logger.debug(f"  _is_component_exported({component_name}): {exc}")
        return False

    def _get_component_permission(self, component_name: str) -> str | None:
        """Return the android:permission attribute for a component, or None.

        Args:
            component_name: Fully-qualified component class name.

        Returns:
            Permission string if present, else None.
        """
        try:
            xml = self._apk.get_android_manifest_xml()
            if xml is None:
                return None
            for elem in xml.iter():
                name_attr = elem.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                if name_attr == component_name or name_attr == component_name.split(".")[-1]:
                    return elem.get(
                        "{http://schemas.android.com/apk/res/android}permission"
                    )
        except Exception as exc:
            logger.debug(f"  _get_component_permission({component_name}): {exc}")
        return None

    # ------------------------------------------------------------------
    # Scan Pass 3: Hardcoded Secrets
    # ------------------------------------------------------------------

    def scan_for_secrets(self) -> list[dict[str, Any]]:
        """Search all string constants in the DEX bytecode for secrets/credentials.

        Iterates over every string in the Dalvik constant pool and applies
        each pattern in SECRET_PATTERNS via regex.

        Returns:
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []
        seen_evidence: set[str] = set()  # Deduplicate identical matches

        # Collect all string constants from DEX
        all_strings: list[str] = []
        if self._analysis:
            for string_analysis in self._analysis.get_strings():
                try:
                    all_strings.append(str(string_analysis.get_value()))
                except Exception:
                    pass

        logger.debug(f"  scanning {len(all_strings)} DEX string constants for secrets…")

        for raw_string in all_strings:
            for pattern_name, pattern, severity in SECRET_PATTERNS:
                try:
                    match = re.search(pattern, raw_string)
                except re.error:
                    continue

                if match:
                    matched_value = match.group(0)
                    # Skip very short or obviously benign matches
                    if len(matched_value) < 6:
                        continue
                    # Deduplicate
                    dedup_key = f"{pattern_name}:{matched_value[:40]}"
                    if dedup_key in seen_evidence:
                        continue
                    seen_evidence.add(dedup_key)

                    # Redact long secrets in the evidence field for safety
                    display_value = (
                        matched_value[:60] + "…" if len(matched_value) > 60
                        else matched_value
                    )

                    findings.append(make_finding(
                        category="SECRET",
                        finding_type="hardcoded_secret",
                        severity_hint=severity,
                        title=f"Potential hardcoded secret: {pattern_name}",
                        location="DEX string constants",
                        evidence=display_value,
                        source="androguard",
                        extra={"pattern": pattern_name},
                    ))

        logger.debug(f"  secrets: {len(findings)} potential matches found")
        return findings

    # ------------------------------------------------------------------
    # Scan Pass 4: Weak/Deprecated Crypto
    # ------------------------------------------------------------------

    def scan_crypto_usage(self) -> list[dict[str, Any]]:
        """Detect weak or deprecated cryptographic API usage in bytecode.

        Strategy:
        1. Find all cross-references (xrefs) to known weak crypto classes.
        2. For MessageDigest.getInstance() and Cipher.getInstance(), inspect
           the string argument to confirm the weak algorithm is actually used.

        Returns:
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []
        if not self._analysis:
            return findings

        seen: set[str] = set()

        for display_name, class_pattern, method_pattern, severity in WEAK_CRYPTO_SIGNATURES:
            try:
                # Find the class in the analysis
                target_class = self._analysis.get_class_analysis(class_pattern)
                if target_class is None:
                    continue

                # Find the specific method
                for method_analysis in target_class.get_methods():
                    if method_pattern not in str(method_analysis.get_method().get_name()):
                        continue

                    # Walk callers (xrefs TO this method)
                    for _, caller_method, _ in method_analysis.get_xref_from():
                        caller_name = (
                            f"{caller_method.get_class_name()}."
                            f"{caller_method.get_name()}"
                        )

                        # Try to extract the string argument to determine algorithm
                        algo_used = self._extract_string_arg_before_call(
                            caller_method, class_pattern, method_pattern
                        )

                        # Filter: only flag genuinely weak algorithms
                        if algo_used and algo_used not in WEAK_ALGO_STRINGS:
                            # Algorithm looks fine (e.g. AES/GCM/NoPadding)
                            continue

                        dedup_key = f"{display_name}:{caller_name}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        evidence = (
                            f'{class_pattern.strip("L;")}.{method_pattern}'
                            f'("{algo_used}")' if algo_used
                            else f'{class_pattern.strip("L;")}.{method_pattern}(…)'
                        )

                        findings.append(make_finding(
                            category="CRYPTO",
                            finding_type="weak_crypto",
                            severity_hint=severity,
                            title=f"Weak/deprecated crypto: {display_name}",
                            location=caller_name,
                            evidence=evidence,
                            source="androguard",
                            extra={"algorithm": algo_used or "unknown"},
                        ))
            except Exception as exc:
                logger.debug(f"  crypto scan error [{display_name}]: {exc}")

        logger.debug(f"  crypto: {len(findings)} weak usages found")
        return findings

    def _extract_string_arg_before_call(
        self,
        method,
        target_class: str,
        target_method: str,
    ) -> str | None:
        """Best-effort extraction of the string constant passed to a method call.

        Walks the bytecode of *method* looking for a const-string instruction
        immediately before an invoke of target_class.target_method.

        Args:
            method:        Androguard Method object of the caller.
            target_class:  Dalvik class descriptor (e.g. 'Ljava/security/MessageDigest;').
            target_method: Method name (e.g. 'getInstance').

        Returns:
            The string constant if found, else None.
        """
        try:
            last_const_string: str | None = None
            for instruction in method.get_instructions():
                op = instruction.get_name()
                if op in ("const-string", "const-string/jumbo"):
                    last_const_string = instruction.get_output().split(",")[-1].strip().strip("'\"")
                elif op.startswith("invoke") and target_method in instruction.get_output():
                    if target_class.strip("L;").replace("/", ".") in instruction.get_output() or \
                       target_class in instruction.get_output():
                        return last_const_string
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Scan Pass 5: Cleartext Traffic
    # ------------------------------------------------------------------

    def scan_cleartext_traffic(self) -> list[dict[str, Any]]:
        """Check manifest and network_security_config.xml for cleartext traffic settings.

        Checks:
        - ``android:usesCleartextTraffic="true"`` in <application> tag
        - ``<base-config cleartextTrafficPermitted="true">`` in NSC XML
        - Target SDK < 28 (cleartext allowed by default before Android 9)

        Returns:
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []

        try:
            xml = self._apk.get_android_manifest_xml()
            if xml is None:
                return findings

            # --- Check usesCleartextTraffic in <application> ---
            app_elem = xml.find("application")
            if app_elem is not None:
                cleartext_attr = app_elem.get(
                    "{http://schemas.android.com/apk/res/android}usesCleartextTraffic"
                )
                if cleartext_attr == "true":
                    findings.append(make_finding(
                        category="NET",
                        finding_type="cleartext_traffic_enabled",
                        severity_hint="High",
                        title="Cleartext (HTTP) traffic explicitly enabled",
                        location="AndroidManifest.xml → <application>",
                        evidence='android:usesCleartextTraffic="true"',
                        source="androguard",
                    ))

                # --- Check networkSecurityConfig reference ---
                nsc_ref = app_elem.get(
                    "{http://schemas.android.com/apk/res/android}networkSecurityConfig"
                )
                if nsc_ref:
                    nsc_findings = self._scan_network_security_config(nsc_ref)
                    findings.extend(nsc_findings)

            # --- Target SDK check ---
            target_sdk = self._apk.get_target_sdk_version()
            if target_sdk and int(target_sdk) < 28:
                findings.append(make_finding(
                    category="NET",
                    finding_type="low_target_sdk_cleartext",
                    severity_hint="Medium",
                    title=f"Target SDK {target_sdk} < 28 — cleartext traffic permitted by default",
                    location="AndroidManifest.xml → <uses-sdk>",
                    evidence=f"android:targetSdkVersion=\"{target_sdk}\"",
                    source="androguard",
                    extra={"target_sdk": target_sdk},
                ))

        except Exception as exc:
            logger.debug(f"  cleartext scan error: {exc}")

        logger.debug(f"  cleartext traffic: {len(findings)} issues found")
        return findings

    def _scan_network_security_config(self, nsc_ref: str) -> list[dict[str, Any]]:
        """Parse a network_security_config.xml file referenced from the manifest.

        Args:
            nsc_ref: Resource reference string (e.g. '@xml/network_security_config').

        Returns:
            List of finding dicts for cleartext-related NSC issues.
        """
        findings: list[dict[str, Any]] = []
        try:
            # Derive filename from resource reference
            xml_name = nsc_ref.split("/")[-1] + ".xml"
            # Try to get it from the APK's file list
            nsc_content: bytes | None = None
            for fname in self._apk.get_files():
                if fname.endswith(xml_name):
                    nsc_content = self._apk.get_file(fname)
                    break

            if nsc_content is None:
                logger.debug(f"  NSC file '{xml_name}' not found in APK")
                return findings

            # Parse XML
            import xml.etree.ElementTree as ET
            nsc_root = ET.fromstring(nsc_content.decode("utf-8", errors="replace"))

            for base_config in nsc_root.iter("base-config"):
                cleartext = base_config.get("cleartextTrafficPermitted", "true")
                if cleartext.lower() == "true":
                    findings.append(make_finding(
                        category="NET",
                        finding_type="nsc_cleartext_permitted",
                        severity_hint="High",
                        title="Network Security Config: cleartext traffic permitted globally",
                        location=f"res/xml/{xml_name} → <base-config>",
                        evidence='cleartextTrafficPermitted="true"',
                        source="androguard",
                    ))

            for domain_config in nsc_root.iter("domain-config"):
                cleartext = domain_config.get("cleartextTrafficPermitted", "false")
                if cleartext.lower() == "true":
                    domains = [d.text for d in domain_config.findall("domain")]
                    findings.append(make_finding(
                        category="NET",
                        finding_type="nsc_domain_cleartext_permitted",
                        severity_hint="Medium",
                        title=f"Network Security Config: cleartext permitted for {len(domains)} domain(s)",
                        location=f"res/xml/{xml_name} → <domain-config>",
                        evidence=f"domains: {', '.join(str(d) for d in domains)}",
                        source="androguard",
                    ))

            # Flag trust-anchors including user certs (certificate pinning bypass risk)
            for trust_anchors in nsc_root.iter("trust-anchors"):
                for cert in trust_anchors.findall("certificates"):
                    src = cert.get("src", "")
                    if src == "user":
                        findings.append(make_finding(
                            category="NET",
                            finding_type="nsc_user_certs_trusted",
                            severity_hint="High",
                            title="Network Security Config trusts user-installed certificates",
                            location=f"res/xml/{xml_name} → <trust-anchors>",
                            evidence='<certificates src="user"/>',
                            source="androguard",
                            extra={"note": "Enables trivial MITM on non-rooted devices via user cert install"},
                        ))

        except Exception as exc:
            logger.debug(f"  NSC parse error: {exc}")

        return findings

    # ------------------------------------------------------------------
    # Optional: JADX Decompilation + Java Source Scan
    # ------------------------------------------------------------------

    def _run_jadx_and_scan(self) -> list[dict[str, Any]]:
        """Decompile the APK with JADX and run regex-based secret scanning on Java source.

        JADX produces higher-fidelity Java source with variable names and
        comments preserved — better for catching secrets embedded in code
        that Androguard's string pool might miss.

        Returns:
            List of additional finding dicts from Java source scanning.
        """
        findings: list[dict[str, Any]] = []

        # Output directory for decompiled source
        jadx_out = self.apk_path.parent / (self.apk_path.stem + "_jadx")
        jadx_out.mkdir(exist_ok=True)

        jadx_bin = self.jadx_path
        if not jadx_bin:
            logger.warning("JADX_PATH not set — skipping JADX scan.")
            return findings

        # Run JADX
        cmd = [jadx_bin, "--output-dir", str(jadx_out), str(self.apk_path)]
        logger.debug(f"  JADX command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute timeout for large APKs
            )
            if result.returncode != 0:
                logger.warning(f"JADX exited with code {result.returncode}: {result.stderr[:500]}")
                return findings
        except FileNotFoundError:
            console.print(
                f"[high]⚠ JADX binary not found at:[/high] {jadx_bin}\n"
                "  Set JADX_PATH in your .env to enable Java source scanning."
            )
            return findings
        except subprocess.TimeoutExpired:
            logger.warning("JADX timed out after 5 minutes.")
            return findings

        # Walk decompiled .java files and apply secret patterns
        java_files = list(jadx_out.rglob("*.java"))
        logger.debug(f"  JADX produced {len(java_files)} Java source files")

        seen_evidence: set[str] = set()

        for java_file in java_files:
            try:
                source = java_file.read_text(encoding="utf-8", errors="replace")
                for line_no, line in enumerate(source.splitlines(), start=1):
                    for pattern_name, pattern, severity in SECRET_PATTERNS:
                        try:
                            match = re.search(pattern, line)
                        except re.error:
                            continue
                        if not match:
                            continue
                        matched_value = match.group(0)
                        if len(matched_value) < 6:
                            continue
                        dedup_key = f"jadx:{pattern_name}:{matched_value[:40]}"
                        if dedup_key in seen_evidence:
                            continue
                        seen_evidence.add(dedup_key)

                        # Build relative location for readability
                        try:
                            rel_path = java_file.relative_to(jadx_out)
                        except ValueError:
                            rel_path = java_file

                        display_value = (
                            matched_value[:60] + "…"
                            if len(matched_value) > 60
                            else matched_value
                        )

                        findings.append(make_finding(
                            category="SECRET",
                            finding_type="hardcoded_secret_java",
                            severity_hint=severity,
                            title=f"Potential hardcoded secret (Java source): {pattern_name}",
                            location=str(rel_path),
                            evidence=display_value,
                            line=line_no,
                            source="jadx",
                            extra={"pattern": pattern_name},
                        ))
            except Exception as exc:
                logger.debug(f"  Error scanning {java_file}: {exc}")

        logger.debug(f"  JADX scan: {len(findings)} additional findings")
        return findings

    # ------------------------------------------------------------------
    # Internal: Stats + Summary
    # ------------------------------------------------------------------

    def _compute_stats(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings by severity.

        Args:
            findings: Full list of finding dicts.

        Returns:
            Dict mapping severity label → count.
        """
        stats: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Total": 0}
        for f in findings:
            # Use CVSS-computed severity if available, fall back to severity_hint
            sev = f.get("severity") or f.get("severity_hint", "Low")
            stats[sev] = stats.get(sev, 0) + 1
            stats["Total"] += 1
        return stats

    def _print_summary(self, stats: dict[str, int]) -> None:
        """Render a coloured summary table to the console.

        Args:
            stats: Output of _compute_stats().
        """
        console.print()
        console.rule("[bold]Scan Complete[/bold]")
        console.print(
            f"  [critical]Critical: {stats['Critical']}[/critical]  "
            f"[high]High: {stats['High']}[/high]  "
            f"[medium]Medium: {stats['Medium']}[/medium]  "
            f"[low]Low: {stats['Low']}[/low]  "
            f"[dim]Total: {stats['Total']}[/dim]"
        )
        console.print()
