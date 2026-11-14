import base64
import hashlib
import json
import re
from pathlib import Path

from universal_dev_security.engine import exit_code_for, overall_status, threshold_reached
from universal_dev_security.findings import Category, Finding, ScanResult, ScanStatus, Severity, cvss_score_to_severity
from universal_dev_security.reports import SCRIPT, build_report, build_sarif, recommendations, render_html, write_reports

SECRET = "NEVER_WRITE_" + "THIS_SECRET"


def make_scan(findings=None, scanners=None, status="findings"):
    findings = findings if findings is not None else [
        Finding(tool="gitleaks", category=Category.SECRET, rule_id="generic-api-key", title="Potential secret",
                file="app/.env", start_line=2).to_dict(),
        Finding(tool="trivy", category=Category.DEPENDENCY, rule_id="CVE-2019-10906", title="<script>alert(1)</script>",
                file="requirements.txt", package="jinja2", installed_version="2.4.1", fixed_version="2.10.1",
                severity=Severity.HIGH, severity_source="scanner",
                references=["https://example.com/a", "javascript:alert(1)"]).to_dict(),
    ]
    return {
        "schema_version": "2.0", "scan_id": "20261114T010000Z-abcdef", "uds_version": "test",
        "started_at": "2026-11-14T01:00:00+00:00", "finished_at": "2026-11-14T01:00:01+00:00",
        "target": "C:/project", "project": {"detected": ["python"]},
        "overall_status": status,
        "scanners": scanners or [
            {"tool": "gitleaks", "status": "findings", "executed": True, "version": "8.30.1", "message": "1", "reason": None, "finding_count": 1},
            {"tool": "trivy", "status": "findings", "executed": True, "version": "0.58.0", "message": "1", "reason": None, "finding_count": 1},
            {"tool": "semgrep", "status": "not_installed", "executed": False, "version": None, "message": "missing", "reason": "executable_not_found", "finding_count": 0},
        ],
        "summary": {"finding_count": len(findings),
                    "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low", "unclassified")},
                    "security_score": None, "score_note": "Not calculated"},
        "coverage": {"executed": ["gitleaks", "trivy"], "not_executed": []},
        "privacy": [], "findings": findings, "limitations": ["A clean result is not proof that the project is secure."],
    }


def test_cvss_qualitative_scale_boundaries():
    assert cvss_score_to_severity("9.0") is Severity.CRITICAL
    assert cvss_score_to_severity(8.9) is Severity.HIGH
    assert cvss_score_to_severity("7.0") is Severity.HIGH
    assert cvss_score_to_severity(4.0) is Severity.MEDIUM
    assert cvss_score_to_severity(0.1) is Severity.LOW
    assert cvss_score_to_severity(0) is Severity.UNCLASSIFIED
    assert cvss_score_to_severity("CVSS:3.1/AV:N") is Severity.UNCLASSIFIED
    assert cvss_score_to_severity(None) is Severity.UNCLASSIFIED


def test_scan_result_cannot_claim_findings_without_execution():
    import pytest
    f = Finding(tool="x", category=Category.CODE, rule_id="r", title="t")
    with pytest.raises(ValueError):
        ScanResult(tool="x", status=ScanStatus.NOT_INSTALLED, findings=[f])
    assert ScanResult(tool="x", status=ScanStatus.CLEAN, findings=[f]).status is ScanStatus.FINDINGS


def test_overall_status_is_honest():
    clean = ScanResult("a", ScanStatus.CLEAN)
    missing = ScanResult("b", ScanStatus.NOT_INSTALLED)
    na = ScanResult("c", ScanStatus.NOT_APPLICABLE)
    err = ScanResult("d", ScanStatus.ERROR)
    found = ScanResult("e", ScanStatus.FINDINGS, [Finding(tool="e", category=Category.CODE, rule_id="r", title="t")])
    assert overall_status([missing, na]) == "not_scanned"
    assert overall_status([clean, na]) == "clean"
    assert overall_status([clean, missing]) == "incomplete"
    assert overall_status([clean, err]) == "error"
    assert overall_status([found, err]) == "findings"


def test_exit_codes_and_thresholds():
    scan = make_scan()
    assert exit_code_for(scan, "none") == 0
    assert exit_code_for(scan, "critical") == 1  # secrets always block once a threshold is set
    scan_no_secret = make_scan(findings=[scan["findings"][1]])
    assert exit_code_for(scan_no_secret, "critical") == 0
    assert exit_code_for(scan_no_secret, "high") == 1
    errored = make_scan(scanners=[{"tool": "gitleaks", "status": "error", "executed": False, "finding_count": 0}], findings=[], status="error")
    assert exit_code_for(errored) == 2
    incomplete = make_scan(findings=[], status="incomplete")
    assert exit_code_for(incomplete) == 0
    assert exit_code_for(incomplete, require_complete=True) == 2
    assert not threshold_reached([], "low")


def test_recommendations_are_data_driven():
    recs = recommendations(make_scan())
    titles = " ".join(r["title"] for r in recs)
    assert "Rotate 1" in titles
    assert "Upgrade 1" in titles
    assert "Install semgrep" in titles


def test_html_escapes_untrusted_values_and_blocks_js_links(tmp_path):
    html = render_html(build_report(make_scan()))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'href="javascript:' not in html
    assert 'href="https://example.com/a"' in html


def test_embedded_json_cannot_break_out_of_script_block():
    scan = make_scan()
    scan["findings"][0]["title"] = "</script><script>alert(1)</script>"
    html = render_html(build_report(scan))
    data_block = html.split('id="uds-data">', 1)[1].split("</script>", 1)[0]
    assert "</script" not in data_block.lower()
    assert json.loads(data_block)["findings"][0]["title"].startswith("</script>")


def test_html_has_csp_with_matching_script_hash_and_no_external_resources():
    html = render_html(build_report(make_scan()))
    from html import unescape
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = unescape(re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1))
    assert f"script-src 'sha256-{digest}'" in csp
    assert "default-src 'none'" in csp
    assert f"<script>{SCRIPT}</script>" in html
    assert not re.search(r"""(?:src|href)=["']https?://(?!example\.com)""", html)
    assert "cdn." not in html.lower()


def test_dashboard_has_required_sections():
    html = render_html(build_report(make_scan()))
    for marker in ('id="search"', 'id="severity-filter"', 'id="tool-filter"', 'id="category-filter"',
                   'id="export-json"', 'id="export-html"', "Scanner coverage", "Recommendations",
                   "Scan history", "Change since previous scan", "--bg:#080d18"):
        assert marker in html
    for sev in ("Critical", "High", "Medium", "Low", "Unclassified"):
        assert f'<div class="label">{sev}</div>' in html
    assert "Not calculated" in html


def test_reports_written_without_secret_values(tmp_path):
    scan = make_scan()
    scan["raw_output"] = SECRET  # unknown keys are carried in JSON, but adapters never produce raw output
    del scan["raw_output"]
    paths = write_reports(build_report(scan), tmp_path, formats=("json", "html", "sarif"))
    for path in paths.values():
        assert SECRET not in Path(path).read_text(encoding="utf-8")
    assert (tmp_path / ".uds" / ".gitignore").is_file()
    assert json.loads(Path(paths["json"]).read_text(encoding="utf-8"))["summary"]["finding_count"] == 2


def test_report_dir_override(tmp_path):
    out = tmp_path / "out"
    paths = write_reports(build_report(make_scan()), tmp_path, out)
    assert Path(paths["html"]).parent == out.resolve()


def test_sarif_structure():
    sarif = build_sarif(make_scan())
    assert sarif["version"] == "2.1.0"
    tools = [run["tool"]["driver"]["name"] for run in sarif["runs"]]
    assert tools == ["UDS / gitleaks", "UDS / trivy"]  # only executed scanners
    secret_result = sarif["runs"][0]["results"][0]
    assert secret_result["level"] == "error"
    assert secret_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert "security-severity" not in json.dumps(sarif)  # no invented numeric scores


def test_clean_report_does_not_claim_security():
    report = build_report(make_scan(findings=[], status="clean", scanners=[
        {"tool": "gitleaks", "status": "clean", "executed": True, "finding_count": 0, "message": ""}]))
    assert any("not proof" in item.lower() for item in report["limitations"])
    assert report["summary"]["security_score"] is None
    assert "not proof of security" in report["recommendations"][0]["detail"]
