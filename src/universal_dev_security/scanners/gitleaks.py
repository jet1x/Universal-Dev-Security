"""Gitleaks adapter: secret detection (https://github.com/gitleaks/gitleaks)."""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from universal_dev_security.findings import Category, Finding, Severity
from universal_dev_security.projectfiles import ProjectInventory
from universal_dev_security.scanners.base import (
    ScannerAdapter,
    ScannerExecutionError,
    ScanOptions,
    relative_path,
    run_tool,
)

# Third-party and UDS-generated content only. Build output (dist/, build/) is
# deliberately still scanned: bundles frequently leak credentials.
SECRET_SCAN_EXCLUDES = (
    ".venv", "venv", "node_modules", "bower_components", "site-packages", ".tox", ".nox", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".terraform", ".git",
)
UDS_GENERATED = (".uds/reports", ".uds/history", ".uds/backups", ".uds/cache")

REMEDIATION = (
    "Treat the credential as compromised: revoke or rotate it with the issuing service, remove it from the "
    "code, load it from an environment variable or secret manager, and if it was committed, purge it from "
    "Git history with an approved history-rewrite procedure."
)


def build_exclusion_config(extra_excludes: list[str]) -> str:
    names = list(SECRET_SCAN_EXCLUDES) + [e.strip("/\\") for e in extra_excludes if e.strip("/\\")]
    parts = [re.escape(name).replace("/", r"[\\/]") for name in names]
    parts += [re.escape(p).replace("/", r"[\\/]") for p in UDS_GENERATED]
    path_regex = r"(?:^|[\\/])(?:" + "|".join(parts) + r")(?:[\\/]|$)"
    if "'''" in path_regex:  # cannot happen with re.escape output, but never emit broken TOML
        raise ScannerExecutionError("Invalid exclusion pattern")
    return (
        'title = "UDS default exclusions"\n\n'
        "[extend]\nuseDefault = true\n\n"
        "[allowlist]\n"
        'description = "Third-party and UDS-generated directories"\n'
        f"paths = ['''{path_regex}''']\n"
    )


def normalize(raw: list[dict[str, Any]], root: Path) -> list[Finding]:
    findings = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or "unknown")[:200]
        # Only metadata is copied. Secret, Match, Line and Entropy are never read.
        findings.append(Finding(
            tool="gitleaks",
            category=Category.SECRET,
            rule_id=rule,
            title=f"Potential secret: {rule}",
            message=str(item.get("Description") or "")[:500],
            file=relative_path(item.get("File"), root),
            start_line=item.get("StartLine"),
            end_line=item.get("EndLine"),
            commit=str(item.get("Commit") or "")[:64] or None,
            severity=Severity.UNCLASSIFIED,
            severity_source="none",
            remediation=REMEDIATION,
            references=["https://github.com/gitleaks/gitleaks"],
        ))
    return findings


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    display_name = "Gitleaks"
    category = Category.SECRET
    executable_names = ("gitleaks",)
    min_version = (8, 19, 0)  # `gitleaks dir` was introduced in 8.19.0
    version_args = ("version",)
    network_note = "runs fully offline."
    docs_url = "https://github.com/gitleaks/gitleaks#installing"
    install_hints = {
        "windows": "winget install --id Gitleaks.Gitleaks -e",
        "macos": "brew install gitleaks",
        "linux": "Download a release from https://github.com/gitleaks/gitleaks/releases and verify its checksum",
    }

    def applicable(self, inventory: ProjectInventory) -> tuple[bool, str]:
        return True, "Secret scanning applies to every project."

    def build_command(self, executable: str, report: Path, config: Path | None) -> list[str]:
        command = [executable, "dir", "--no-banner", "--redact", "--exit-code", "1",
                   "--report-format", "json", "--report-path", str(report)]
        if config is not None:
            command += ["--config", str(config)]
        return command + ["."]

    def execute(self, executable: str, version: str, target: Path, options: ScanOptions) -> list[Finding]:
        with tempfile.TemporaryDirectory(prefix="uds-gitleaks-") as temp_dir:
            report = Path(temp_dir) / "gitleaks-report.json"
            config: Path | None = None
            # Respect a project-provided Gitleaks configuration instead of overriding it.
            if not (target / ".gitleaks.toml").is_file():
                config = Path(temp_dir) / "uds-gitleaks.toml"
                config.write_text(build_exclusion_config(options.exclude_paths), encoding="utf-8")
            completed = run_tool(self.build_command(executable, report, config), cwd=target,
                                 timeout=options.timeout_seconds)
            if completed.returncode not in (0, 1):
                raise ScannerExecutionError(
                    f"Gitleaks exited with code {completed.returncode}; raw output was suppressed."
                )
            if not report.is_file():
                if completed.returncode == 0:
                    return []
                raise ScannerExecutionError("Gitleaks reported leaks but produced no report file.")
            try:
                data = json.loads(report.read_text(encoding="utf-8") or "[]")
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise ScannerExecutionError("Gitleaks report could not be parsed; raw output was suppressed.") from exc
        if not isinstance(data, list):
            raise ScannerExecutionError("Gitleaks report has an unexpected format.")
        findings = normalize(data, target)
        if completed.returncode == 1 and not findings:
            raise ScannerExecutionError("Gitleaks signalled leaks but the report contained none.")
        return findings
