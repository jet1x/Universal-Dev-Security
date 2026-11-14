"""Trivy adapter: dependency vulnerabilities and misconfiguration (https://trivy.dev)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from universal_dev_security.detector import has_dependency_manifests, has_iac
from universal_dev_security.findings import Category, Finding, Severity
from universal_dev_security.projectfiles import ProjectInventory
from universal_dev_security.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScanOptions,
    relative_path,
    run_tool,
)

# Trivy reports CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN natively.
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _refs(item: dict[str, Any]) -> list[str]:
    refs = []
    if item.get("PrimaryURL"):
        refs.append(str(item["PrimaryURL"]))
    refs.extend(str(r) for r in (item.get("References") or [])[:5] if isinstance(r, str))
    return refs


def _severity(item: dict[str, Any]) -> tuple[Severity, str | None]:
    raw = str(item.get("Severity") or "").upper()
    return SEVERITY_MAP.get(raw, Severity.UNCLASSIFIED), raw or None


def normalize(data: dict[str, Any], root: Path) -> list[Finding]:
    results = data.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise ScannerExecutionError("Trivy output has an unexpected format.")
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target_file = relative_path(result.get("Target"), root)
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            severity, raw = _severity(vuln)
            pkg = str(vuln.get("PkgName") or "unknown")[:200]
            fixed = str(vuln.get("FixedVersion") or "")[:200] or None
            findings.append(Finding(
                tool="trivy", category=Category.DEPENDENCY,
                rule_id=str(vuln.get("VulnerabilityID") or "unknown")[:100],
                title=str(vuln.get("Title") or f"Known vulnerability in {pkg}")[:300],
                message=str(vuln.get("Description") or "")[:800],
                file=target_file, package=pkg,
                installed_version=str(vuln.get("InstalledVersion") or "")[:100] or None,
                fixed_version=fixed, severity=severity,
                severity_source="scanner" if severity is not Severity.UNCLASSIFIED else "none",
                scanner_severity=raw, references=_refs(vuln),
                remediation=(f"Upgrade {pkg} to {fixed} or later, then run the test suite."
                             if fixed else f"No fixed version is listed; assess exposure of {pkg}."),
            ))
        for misconf in result.get("Misconfigurations") or []:
            if not isinstance(misconf, dict) or str(misconf.get("Status") or "FAIL").upper() == "PASS":
                continue
            severity, raw = _severity(misconf)
            cause = misconf.get("CauseMetadata") if isinstance(misconf.get("CauseMetadata"), dict) else {}
            findings.append(Finding(
                tool="trivy", category=Category.CONFIGURATION,
                rule_id=str(misconf.get("AVDID") or misconf.get("ID") or "unknown")[:100],
                title=str(misconf.get("Title") or "Misconfiguration")[:300],
                message=str(misconf.get("Message") or misconf.get("Description") or "")[:800],
                file=target_file, start_line=cause.get("StartLine"), end_line=cause.get("EndLine"),
                severity=severity,
                severity_source="scanner" if severity is not Severity.UNCLASSIFIED else "none",
                scanner_severity=raw, references=_refs(misconf),
                remediation=str(misconf.get("Resolution") or "Apply the documented secure configuration.")[:500],
            ))
    return findings


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    display_name = "Trivy"
    category = Category.CONFIGURATION
    executable_names = ("trivy",)
    min_version = (0, 45, 0)
    downloads_data = True
    network_note = ("downloads its vulnerability database and misconfiguration checks; "
                    "project files are analysed locally and are not uploaded.")
    docs_url = "https://trivy.dev/latest/getting-started/installation/"
    install_hints = {
        "windows": "winget install --id AquaSecurity.Trivy -e",
        "macos": "brew install trivy",
        "linux": "Use the official repository or release from https://trivy.dev/latest/getting-started/installation/",
    }

    def applicable(self, inventory: ProjectInventory) -> tuple[bool, str]:
        reasons = []
        if has_dependency_manifests(inventory):
            reasons.append("dependency manifests")
        if has_iac(inventory):
            reasons.append("container / infrastructure-as-code files")
        if reasons:
            return True, "Detected " + " and ".join(reasons) + "."
        return False, "No dependency manifests or infrastructure-as-code files were found."

    def build_command(self, executable: str, report: Path, options: ScanOptions) -> list[str]:
        # Secret scanning is handled by Gitleaks; Trivy's secret output includes matched text.
        command = [executable, "fs", "--quiet", "--format", "json", "--output", str(report),
                   "--scanners", "vuln,misconfig", "--exit-code", "0"]
        skip = [d for d in options.excluded_dirs if d != ".git"]
        if skip:
            command += ["--skip-dirs", ",".join(skip)]
        return command + ["."]

    def execute(self, executable: str, version: str, target: Path, options: ScanOptions) -> list[Finding]:
        with tempfile.TemporaryDirectory(prefix="uds-trivy-") as temp_dir:
            report = Path(temp_dir) / "trivy.json"
            completed = run_tool(self.build_command(executable, report, options), cwd=target,
                                 timeout=options.timeout_seconds)
            if completed.returncode != 0:
                raise ScannerExecutionError(f"Trivy exited with code {completed.returncode}; raw output was suppressed.")
            try:
                data = json.loads(report.read_text(encoding="utf-8") or "{}")
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise ScannerExecutionError("Trivy report could not be parsed; raw output was suppressed.") from exc
        if not isinstance(data, dict):
            raise ScannerExecutionError("Trivy output has an unexpected format.")
        return normalize(data, target)
