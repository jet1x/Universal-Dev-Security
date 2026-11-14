import pytest

from universal_dev_security.findings import Category, Finding
from universal_dev_security.history import compare_scans, list_scans, load_scan, resolve_scan_id, save_scan


def scan(scan_id, findings, executed):
    return {"scan_id": scan_id, "overall_status": "findings" if findings else "clean",
            "summary": {"finding_count": len(findings), "by_severity": {}},
            "coverage": {"executed": executed}, "findings": findings}


def f(tool, rule, file="a.py", line=1):
    return Finding(tool=tool, category=Category.CODE, rule_id=rule, title=rule, file=file, start_line=line).to_dict()


def test_save_list_load_and_prune(tmp_path):
    for i in range(5):
        save_scan(tmp_path, scan(f"20261114T01000{i}Z-abcdef", [], ["gitleaks"]), limit=3)
    assert list_scans(tmp_path) == [f"20261114T01000{i}Z-abcdef" for i in (2, 3, 4)]
    assert load_scan(tmp_path, "latest")["scan_id"].startswith("20261114T010004Z")
    assert resolve_scan_id(tmp_path, "previous") == "20261114T010003Z-abcdef"
    assert (tmp_path / ".uds" / ".gitignore").is_file()


def test_scan_id_validation_prevents_traversal(tmp_path):
    save_scan(tmp_path, scan("20261114T010000Z-abcdef", [], []))
    for bad in ("../../etc/passwd", "..\\config", "latest/../x", "20261114T010000Z-abcdeg"):
        with pytest.raises(ValueError):
            load_scan(tmp_path, bad)
    with pytest.raises(ValueError):
        save_scan(tmp_path, scan("../evil", [], []))


def test_no_history_errors_cleanly(tmp_path):
    with pytest.raises(ValueError, match="No scan history"):
        load_scan(tmp_path, "latest")


def test_compare_new_resolved_unchanged_and_line_moves():
    base = scan("b", [f("semgrep", "r1", line=1), f("semgrep", "r2")], ["semgrep"])
    head = scan("h", [f("semgrep", "r1", line=40), f("semgrep", "r3")], ["semgrep"])
    result = compare_scans(base, head)
    assert [x["rule_id"] for x in result["new"]] == ["r3"]
    assert [x["rule_id"] for x in result["resolved"]] == ["r2"]
    assert result["unchanged_count"] == 1  # moved line is not a "new" finding


def test_findings_from_scanner_not_rerun_are_not_marked_resolved():
    base = scan("b", [f("trivy", "CVE-1"), f("gitleaks", "key")], ["trivy", "gitleaks"])
    head = scan("h", [f("gitleaks", "key")], ["gitleaks"])  # trivy not executed this time
    result = compare_scans(base, head)
    assert result["resolved"] == []
    assert [x["rule_id"] for x in result["not_rescanned"]] == ["CVE-1"]


def test_rapid_successive_scans_keep_order(tmp_path, monkeypatch):
    # Regression: ids used second resolution, so two scans in the same second could swap order.
    from universal_dev_security.engine import run_scan
    from universal_dev_security.scanners import base
    monkeypatch.setattr(base, "find_executable", lambda tool, names: (None, None))
    ids = []
    for _ in range(5):
        result = run_scan(tmp_path)
        save_scan(tmp_path, result)
        ids.append(result["scan_id"])
    assert list_scans(tmp_path) == ids
    assert resolve_scan_id(tmp_path, "latest") == ids[-1]
    assert resolve_scan_id(tmp_path, "previous") == ids[-2]
