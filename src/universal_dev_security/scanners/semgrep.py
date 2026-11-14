"""Semgrep adapter: static code analysis (https://semgrep.dev)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from universal_dev_security.detector import has_source_code, recommended_semgrep_configs
from universal_dev_security.findings import Category, Finding, Severity
from universal_dev_security.projectfiles import ProjectInventory
from universal_dev_security.redaction import redact
from universal_dev_security.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScanOptions,
    relative_path,
    run_tool,
)

# Semgrep rule severities. Current Semgrep rules may use CRITICAL/HIGH/MEDIUM/LOW
# directly; legacy values are documented by Semgrep as ERROR=High,
# WARNING=Medium, INFO=Low. Anything else stays unclassified.
SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.LOW,
}


def _strings(value: Any, limit: int = 10) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int, float))][:limit]
    return []


def normalize(data: dict[str, Any], root: Path) -> list[Finding]:
    results = data.get("results")
    if not isinstance(results, list):
        raise ScannerExecutionError("Semgrep output has an unexpected format.")
    findings = []
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        raw_severity = str(extra.get("severity") or "").upper()
        severity = SEVERITY_MAP.get(raw_severity, Severity.UNCLASSIFIED)
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        end = item.get("end") if isinstance(item.get("end"), dict) else {}
        rule_id = str(item.get("check_id") or "unknown")[:300]
        cwe = ", ".join(_strings(metadata.get("cwe"), 3))
        references = _strings(metadata.get("references")) + _strings(metadata.get("source"), 1)
        message = redact(str(extra.get("message") or ""))[:800]  # messages can interpolate matched code
        findings.append(Finding(
            tool="semgrep",
            category=Category.CODE,
            rule_id=rule_id,
            title=rule_id.rsplit(".", 1)[-1].replace("-", " ").capitalize()[:200],
            message=message,
            file=relative_path(item.get("path"), root),
            start_line=start.get("line"),
            end_line=end.get("line"),
            severity=severity,
            severity_source="scanner" if severity is not Severity.UNCLASSIFIED else "none",
            scanner_severity=raw_severity or None,
            references=references,
            remediation=("Review the flagged code and apply the rule guidance" + (f" ({cwe})." if cwe else ".")),
        ))
    return findings


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    display_name = "Semgrep"
    category = Category.CODE
    executable_names = ("semgrep",)
    min_version = (1, 0, 0)
    downloads_data = True
    network_note = ("downloads rule packs from the Semgrep Registry when registry configs are used; "
                    "UDS disables Semgrep metrics and does not upload source code.")
    docs_url = "https://semgrep.dev/docs/getting-started/quickstart"
    install_hints = {
        "windows": "python -m pip install semgrep  (inside the UDS virtual environment)",
        "macos": "brew install semgrep  or  python3 -m pip install semgrep",
        "linux": "python3 -m pip install semgrep",
    }

    def applicable(self, inventory: ProjectInventory) -> tuple[bool, str]:
        if has_source_code(inventory):
            return True, "Source code files detected."
        return False, "No source code files supported by Semgrep were found."

    def configs(self, options: ScanOptions) -> list[str]:
        configs = options.semgrep_configs or recommended_semgrep_configs(options.technologies)
        # `--config auto` requires sending metrics to Semgrep; replace it with the default pack.
        return [("p/default" if c.strip().lower() == "auto" else c.strip()) for c in configs if c.strip()][:20]

    def build_command(self, executable: str, options: ScanOptions) -> list[str]:
        command = [executable, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
                   "--timeout", "30"]
        for config in self.configs(options):
            command += ["--config", config]
        for excluded in options.excluded_dirs:
            if excluded != ".git":
                command += ["--exclude", excluded]
        return command + ["."]

    def execute(self, executable: str, version: str, target: Path, options: ScanOptions) -> list[Finding]:
        env = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        if os.name == "nt":
            env["PYTHONUTF8"] = "1"
        completed = run_tool(self.build_command(executable, options), cwd=target,
                             timeout=options.timeout_seconds, env_overrides=env)
        # 0 = success, 1 = findings with --error. Everything else is a failure.
        if completed.returncode not in (0, 1):
            raise ScannerExecutionError(f"Semgrep exited with code {completed.returncode}; raw output was suppressed.")
        try:
            data = json.loads(completed.stdout or "")
        except ValueError as exc:
            raise ScannerExecutionError("Semgrep output could not be parsed; raw output was suppressed.") from exc
        if not isinstance(data, dict):
            raise ScannerExecutionError("Semgrep output has an unexpected format.")
        return normalize(data, target)
