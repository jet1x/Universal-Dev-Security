"""Backwards-compatible API from UDS 0.4.x.

New code should use :mod:`universal_dev_security.scanners` and
:func:`universal_dev_security.engine.run_scan`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from universal_dev_security.projectfiles import build_inventory
from universal_dev_security.scanners.base import ScanOptions, find_executable
from universal_dev_security.scanners.gitleaks import GitleaksAdapter


def find_gitleaks() -> str | None:
    return find_executable("gitleaks", ("gitleaks",))[0]


def scan_with_gitleaks(target: Path) -> dict[str, Any]:
    """Run Gitleaks and return the 0.4.x result dictionary (sanitized)."""
    resolved = target.expanduser().resolve()
    if not resolved.is_dir():
        raise ValueError(f"Scan target is not an existing directory: {resolved}")
    result = GitleaksAdapter().scan(resolved, build_inventory(resolved), ScanOptions())
    return {
        "tool": "gitleaks",
        "status": result.status.value,
        "findings": [
            {"rule_id": f.rule_id, "file": f.file, "start_line": f.start_line, "end_line": f.end_line,
             "commit": f.commit or ""}
            for f in result.findings
        ],
        "finding_count": result.finding_count,
        "message": result.message,
    }
