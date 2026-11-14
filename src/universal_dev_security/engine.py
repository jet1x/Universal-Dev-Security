"""Scan orchestration: run applicable scanners and aggregate honest results."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from universal_dev_security import __version__
from universal_dev_security.config import FAIL_ON_LEVELS, ProjectConfig
from universal_dev_security.detector import detect_project
import hashlib
import json
import shutil
import subprocess

from universal_dev_security.findings import Category, Finding, ScanResult, ScanStatus, Severity, severity_counts
from universal_dev_security.projectfiles import build_inventory
from universal_dev_security.scanners import get_scanner
from universal_dev_security.scanners.base import ScannerExecutionError, ScanOptions, run_tool

SCHEMA_VERSION = "2.0"


def overall_status(results: list[ScanResult]) -> str:
    """Aggregate scanner states without overstating coverage.

    * ``not_scanned`` - no scanner executed.
    * ``findings``    - at least one executed scanner returned findings.
    * ``error``       - no findings, but at least one scanner failed.
    * ``incomplete``  - no findings or errors, but an applicable scanner did not run.
    * ``clean``       - every applicable scanner executed and returned nothing.
    """
    executed = [r for r in results if r.status.executed]
    if not executed:
        return "not_scanned"
    if any(r.status is ScanStatus.FINDINGS for r in results):
        return "findings"
    if any(r.status is ScanStatus.ERROR for r in results):
        return "error"
    if any(r.status in (ScanStatus.NOT_INSTALLED, ScanStatus.SKIPPED) for r in results):
        return "incomplete"
    return "clean"


def scope_fingerprint(extra_excludes: list[str]) -> str:
    """Identify the scan scope (built-in and configured exclusions).

    When it differs between two scans, findings that disappeared may have been
    excluded rather than fixed, and comparisons must say so.
    """
    from universal_dev_security.projectfiles import DEFAULT_EXCLUDED_DIRS
    from universal_dev_security.scanners.gitleaks import SECRET_SCAN_EXCLUDES

    basis = json.dumps([sorted(DEFAULT_EXCLUDED_DIRS), list(SECRET_SCAN_EXCLUDES), sorted(extra_excludes)])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def git_tracked_files(root: Path) -> set[str] | None:
    """Project-relative paths tracked by Git, or None when ``root`` is not inside a Git work tree."""
    git = shutil.which("git")
    if not git:
        return None
    try:
        completed = run_tool([git, "ls-files", "-z"], cwd=root, timeout=120)
    except (OSError, subprocess.SubprocessError, ScannerExecutionError):
        return None
    if completed.returncode != 0:
        return None
    return {path.replace("\\", "/") for path in completed.stdout.split("\0") if path}


def annotate_git_exposure(root: Path, findings: list[Finding]) -> None:
    """Mark secret findings as committed (tracked by Git) or local-only.

    A secret in a tracked file has been (or will be) shared through the
    repository and must be rotated; one in an untracked or ignored local file
    has not left the machine through Git.
    """
    secrets = [f for f in findings if f.category is Category.SECRET]
    if not secrets:
        return
    tracked = git_tracked_files(root)
    for finding in secrets:
        if finding.commit:
            finding.tracked_in_git = True  # found in Git history
        elif tracked is not None:
            finding.tracked_in_git = finding.file in tracked


def finding_sort_key(finding: Finding) -> tuple[int, int, str, str, int]:
    """Committed secrets first, then by severity (critical → unclassified), tool, file, line."""
    exposed = 0 if (finding.category is Category.SECRET and finding.tracked_in_git) else 1
    return (exposed, -finding.severity.rank, finding.tool, finding.file, finding.start_line or 0)


def threshold_reached(findings: list[Finding], fail_on: str) -> bool:
    if fail_on not in FAIL_ON_LEVELS or fail_on == "none":
        return False
    if fail_on == "unclassified":
        return bool(findings)
    threshold = Severity(fail_on).rank
    # Unclassified secrets are always treated as blocking once a threshold is set:
    # an exposed credential is never "low risk" just because it lacks a label.
    return any(f.severity.rank >= threshold or (f.category.value == "secret") for f in findings)


def run_scan(
    target: Path,
    config: ProjectConfig | None = None,
    *,
    tools: list[str] | None = None,
    allow_network: bool | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    root = target.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Scan target is not an existing directory: {root}")
    config = config or ProjectConfig()
    started = datetime.now(timezone.utc)
    inventory = build_inventory(root, extra_excludes=config.exclude_paths)
    project = detect_project(root, inventory)
    options = ScanOptions(
        timeout_seconds=config.scanner_timeout_seconds,
        allow_network=config.allow_network if allow_network is None else allow_network,
        semgrep_configs=config.semgrep_configs,
        exclude_paths=config.exclude_paths,
        technologies=project["detected"],
    )
    requested = tools or config.enabled_scanners
    results: list[ScanResult] = []
    for name in requested:
        adapter = get_scanner(name)
        if progress:
            progress(f"Running {adapter.display_name}...")
        results.append(adapter.scan(root, inventory, options))

    findings = [finding for result in results for finding in result.findings]
    annotate_git_exposure(root, findings)
    findings.sort(key=finding_sort_key)
    status = overall_status(results)
    counts = severity_counts(findings)
    privacy = []
    for name in requested:
        adapter = get_scanner(name)
        privacy.append({
            "tool": name,
            "transmits_project_metadata": adapter.transmits_project_metadata,
            "downloads_data": adapter.downloads_data,
            "note": adapter.network_note,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        # Microseconds keep ids strictly ordered even for scans started within the same second.
        "scan_id": started.strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:6],
        "uds_version": __version__,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target": str(root),
        "project": {
            "detected": project["detected"],
            "files_inventoried": project["files_inventoried"],
            "inventory_truncated": project["inventory_truncated"],
        },
        "options": {"tools": requested, "allow_network": options.allow_network, "fail_on": config.fail_on,
                    "scope_fingerprint": scope_fingerprint(config.exclude_paths)},
        "overall_status": status,
        "scanners": [{k: v for k, v in r.to_dict().items() if k != "findings"} for r in results],
        "summary": {
            "finding_count": len(findings),
            "by_severity": counts,
            "by_tool": {r.tool: r.finding_count for r in results},
            "by_category": {c: sum(1 for f in findings if f.category.value == c)
                            for c in ("secret", "code", "dependency", "configuration")},
            "security_score": None,
            "score_note": "Not calculated: UDS does not publish a numeric score without a validated, documented methodology.",
        },
        "coverage": {
            "executed": [r.tool for r in results if r.status.executed],
            "not_executed": [{"tool": r.tool, "status": r.status.value, "reason": r.reason} for r in results
                             if not r.status.executed],
        },
        "privacy": privacy,
        "findings": [f.to_dict() for f in findings],
        "limitations": [
            "This report covers only the scanners listed as executed.",
            "A clean result is not proof that the project is secure.",
            "Severity is shown only when supplied by the scanner or derived from a published scale (CVSS); "
            "other findings are unclassified.",
            "Secret values, matched text and raw scanner output are intentionally excluded.",
        ],
    }


def exit_code_for(scan: dict[str, Any], fail_on: str = "none", require_complete: bool = False) -> int:
    """0 = success, 1 = findings at/above threshold, 2 = scan error / nothing scanned / incomplete (if required)."""
    status = scan["overall_status"]
    if status in ("not_scanned", "error") or any(s["status"] == "error" for s in scan["scanners"]):
        return 2
    if require_complete and status == "incomplete":
        return 2
    findings = [Finding.from_dict(f) for f in scan["findings"]]
    return 1 if threshold_reached(findings, fail_on) else 0
