"""OSV-Scanner adapter: dependency vulnerabilities (https://google.github.io/osv-scanner/)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from universal_dev_security.detector import has_dependency_manifests
from universal_dev_security.findings import Category, Finding, Severity, cvss_score_to_severity
from universal_dev_security.projectfiles import ProjectInventory
from universal_dev_security.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScanOptions,
    parse_version,
    relative_path,
    run_tool,
)

# GitHub Advisory Database severities, used only when no CVSS score is present.
ADVISORY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
EXIT_NO_PACKAGES = 128


def _fixed_version(vuln: dict[str, Any], package_name: str) -> str | None:
    affected = vuln.get("affected") if isinstance(vuln.get("affected"), list) else []
    fixed: list[str] = []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        if pkg.get("name") and str(pkg.get("name")).lower() != package_name.lower():
            continue
        for rng in entry.get("ranges") or []:
            for event in (rng.get("events") or []) if isinstance(rng, dict) else []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    return ", ".join(dict.fromkeys(fixed))[:200] or None


def normalize(data: dict[str, Any], root: Path) -> list[Finding]:
    results = data.get("results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise ScannerExecutionError("OSV-Scanner output has an unexpected format.")
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source") if isinstance(result.get("source"), dict) else {}
        file = relative_path(source.get("path"), root)
        for pkg_entry in result.get("packages") or []:
            if not isinstance(pkg_entry, dict):
                continue
            package = pkg_entry.get("package") if isinstance(pkg_entry.get("package"), dict) else {}
            name = str(package.get("name") or "unknown")[:200]
            version = str(package.get("version") or "")[:100] or None
            ecosystem = str(package.get("ecosystem") or "")[:50]
            vulns = {str(v.get("id")): v for v in pkg_entry.get("vulnerabilities") or [] if isinstance(v, dict)}
            groups = [g for g in pkg_entry.get("groups") or [] if isinstance(g, dict)]
            if not groups:  # older output: one group per vulnerability
                groups = [{"ids": [vid], "max_severity": ""} for vid in vulns]
            for group in groups:
                ids = [str(i) for i in group.get("ids") or []]
                if not ids:
                    continue
                primary = next((i for i in ids if i.startswith("GHSA-")), ids[0])
                vuln = vulns.get(primary) or vulns.get(ids[0]) or {}
                severity = cvss_score_to_severity(group.get("max_severity"))
                severity_source = "cvss-qualitative-scale" if severity is not Severity.UNCLASSIFIED else "none"
                db_specific = vuln.get("database_specific") if isinstance(vuln.get("database_specific"), dict) else {}
                if severity is Severity.UNCLASSIFIED:
                    advisory = str(db_specific.get("severity") or "").upper()
                    if advisory in ADVISORY_SEVERITY:
                        severity, severity_source = ADVISORY_SEVERITY[advisory], "advisory-database"
                aliases = [str(a) for a in (group.get("aliases") or vuln.get("aliases") or [])][:10]
                references = [str(r.get("url")) for r in vuln.get("references") or []
                              if isinstance(r, dict) and r.get("url")]
                references.insert(0, f"https://osv.dev/vulnerability/{primary}")
                fixed = _fixed_version(vuln, name)
                findings.append(Finding(
                    tool="osv-scanner",
                    category=Category.DEPENDENCY,
                    rule_id=primary[:100],
                    title=str(vuln.get("summary") or f"Known vulnerability in {name}")[:300],
                    message=f"{ecosystem} package {name} {version or ''} is affected by {', '.join(ids[:5])}"
                            + (f" (aliases: {', '.join(aliases[:5])})" if aliases else "") + ".",
                    file=file,
                    package=name,
                    installed_version=version,
                    fixed_version=fixed,
                    severity=severity,
                    severity_source=severity_source,
                    scanner_severity=str(group.get("max_severity") or db_specific.get("severity") or "") or None,
                    references=references,
                    remediation=(f"Upgrade {name} to {fixed} or later, then run the test suite."
                                 if fixed else f"No fixed version is listed; assess exposure and consider replacing {name}."),
                ))
    return findings


class OsvScannerAdapter(ScannerAdapter):
    name = "osv-scanner"
    display_name = "OSV-Scanner"
    category = Category.DEPENDENCY
    executable_names = ("osv-scanner",)
    min_version = (1, 4, 0)
    transmits_project_metadata = True
    downloads_data = True
    network_note = "sends package names and versions (not source code) to the osv.dev API."
    docs_url = "https://google.github.io/osv-scanner/installation/"
    install_hints = {
        "windows": "winget install --id Google.OSVScanner -e  or download from https://github.com/google/osv-scanner/releases",
        "macos": "brew install osv-scanner",
        "linux": "Download a release from https://github.com/google/osv-scanner/releases and verify its checksum",
    }

    def applicable(self, inventory: ProjectInventory) -> tuple[bool, str]:
        if has_dependency_manifests(inventory):
            return True, "Dependency manifests or lockfiles detected."
        return False, "No dependency manifests or lockfiles were found."

    def build_command(self, executable: str, version: str, options: ScanOptions) -> list[str]:
        parsed = parse_version(version) or (0, 0, 0)
        command = [executable]
        if parsed >= (2, 0, 0):
            command += ["scan", "source"]
        command += ["--format", "json", "--recursive"]
        return command + ["."]

    def execute(self, executable: str, version: str, target: Path, options: ScanOptions) -> list[Finding]:
        completed = run_tool(self.build_command(executable, version, options), cwd=target,
                             timeout=options.timeout_seconds)
        if completed.returncode == EXIT_NO_PACKAGES:
            return []
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(
                f"OSV-Scanner exited with code {completed.returncode}; raw output was suppressed."
            )
        try:
            data = json.loads(completed.stdout or "{}")
        except ValueError as exc:
            raise ScannerExecutionError("OSV-Scanner output could not be parsed; raw output was suppressed.") from exc
        if not isinstance(data, dict):
            raise ScannerExecutionError("OSV-Scanner output has an unexpected format.")
        findings = normalize(data, target)
        if completed.returncode == 1 and not findings:
            raise ScannerExecutionError("OSV-Scanner reported vulnerabilities but none could be parsed.")
        return findings
