"""Regressions from the first live scan of a real Next.js project.

Findings that motivated these tests:
* 97% of secret findings came from .next/cache and .next/dev (never deployed);
* the report said "Rotate 708 credentials" although none were committed;
* the only finding with a severity was listed below 708 unclassified ones;
* a scanner that did not run showed "0" findings in the coverage table.
"""
import re
import shutil
import subprocess

import pytest

from universal_dev_security.engine import annotate_git_exposure, finding_sort_key, git_tracked_files
from universal_dev_security.findings import Category, Finding, Severity
from universal_dev_security.reports import build_report, recommendations, render_html
from universal_dev_security.scanners.gitleaks import build_exclusion_config


def secret(file, tracked=None, commit=None):
    f = Finding(tool="gitleaks", category=Category.SECRET, rule_id="generic-api-key", title="Potential secret",
                file=file, start_line=1, commit=commit)
    f.tracked_in_git = tracked
    return f


@pytest.mark.parametrize("path,excluded", [
    (".next/cache/webpack/client/0.pack", True),
    (".next/dev/server/app/page.js", True),
    ("apps/web/.next/cache/x", True),
    (".turbo/cache/x", True),
    (".next/static/chunks/main.js", False),   # served to browsers: must stay scanned
    (".next/server/app/page.js", False),      # deployed server bundle: must stay scanned
    ("src/.nextcache.js", False),
])
def test_framework_caches_excluded_but_deployable_output_scanned(path, excluded):
    import tomllib
    pattern = tomllib.loads(build_exclusion_config([]))["allowlist"]["paths"][0]
    assert bool(re.search(pattern, path)) is excluded


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is not installed")
def test_secrets_are_marked_committed_or_local(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "config.py").write_text("x\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.py"], cwd=tmp_path, check=True)
    assert git_tracked_files(tmp_path) == {"config.py"}
    findings = [secret("config.py"), secret(".env.local"), secret("old.py", commit="abc123")]
    annotate_git_exposure(tmp_path, findings)
    assert [f.tracked_in_git for f in findings] == [True, False, True]


def test_exposure_unknown_without_git(tmp_path, monkeypatch):
    from universal_dev_security import engine
    monkeypatch.setattr(engine.shutil, "which", lambda name: None)
    findings = [secret("a.py"), secret("b.py", commit="abc123")]
    annotate_git_exposure(tmp_path, findings)
    assert [f.tracked_in_git for f in findings] == [None, True]  # history findings are always committed


def test_recommendations_distinguish_committed_and_local_secrets():
    findings = [secret("app.py", True).to_dict()] + [secret(f".env{i}", False).to_dict() for i in range(3)]
    titles = [r["title"] for r in recommendations({"findings": findings, "scanners": []})]
    assert "Rotate 1 credential(s) found in Git-tracked files" in titles
    assert "3 potential secret(s) in local files not tracked by Git" in titles
    local_only = recommendations({"findings": findings[1:], "scanners": []})
    assert not any(r["priority"] == "urgent" for r in local_only)


def test_sort_puts_committed_secrets_then_severity_first():
    medium = Finding(tool="osv-scanner", category=Category.DEPENDENCY, rule_id="GHSA-1", title="t",
                     severity=Severity.MEDIUM, file="package-lock.json")
    items = [secret(".env", False), medium, secret("app.py", True)]
    ordered = sorted(items, key=finding_sort_key)
    assert [f.file for f in ordered] == ["app.py", "package-lock.json", ".env"]


def test_dashboard_shows_exposure_and_dash_for_scanners_that_did_not_run():
    scan = {
        "scan_id": "20261114T010000Z-abcdef", "overall_status": "findings", "summary": {"by_severity": {}},
        "scanners": [{"tool": "semgrep", "status": "not_installed", "executed": False, "finding_count": 0, "message": "m"},
                     {"tool": "gitleaks", "status": "findings", "executed": True, "finding_count": 2, "message": "m"}],
        "findings": [secret("app.py", True).to_dict(), secret(".env", False).to_dict()],
    }
    html = render_html(build_report(scan))
    assert "<td>—</td>" in html
    assert ">in Git</span>" in html and ">local only</span>" in html
    assert "Not tracked by Git — local file only" in html


def test_comparison_warns_when_scan_scope_changed():
    from universal_dev_security.history import compare_scans
    gone = secret(".next/cache/x", False).to_dict()

    def scan(fp, findings):
        return {"scan_id": "s", "options": {"scope_fingerprint": fp}, "coverage": {"executed": ["gitleaks"]},
                "findings": findings}

    changed = compare_scans(scan("aaa", [gone]), scan("bbb", []))
    assert changed["scope_changed"] and len(changed["resolved"]) == 1
    assert "excluded rather than fixed" in changed["warnings"][0]
    same = compare_scans(scan("aaa", [gone]), scan("aaa", []))
    assert same["warnings"] == []
    legacy = compare_scans({k: v for k, v in scan("x", [gone]).items() if k != "options"}, scan("aaa", []))
    assert legacy["warnings"]  # scans without a recorded scope are treated as possibly different
    html = render_html(build_report({"scan_id": "s", "overall_status": "clean", "summary": {}, "scanners": [],
                                     "findings": []}, changed))
    assert html.index("excluded rather than fixed") < html.index("Resolved")
