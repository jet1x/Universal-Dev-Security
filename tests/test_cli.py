"""CLI tests, executed in-process and (for the entry point) as a real subprocess."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from universal_dev_security import __version__
from universal_dev_security.cli import main
from universal_dev_security.scanner import find_gitleaks


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_version_via_module_subprocess():
    completed = subprocess.run([sys.executable, "-m", "universal_dev_security", "--version"],
                               capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0
    assert __version__ in completed.stdout


def test_doctor_json(capsys, tmp_path):
    code, out, _ = run(capsys, "doctor", str(tmp_path), "--json")
    data = json.loads(out)
    assert code == 0
    assert {s["name"] for s in data["scanners"]} == {"gitleaks", "semgrep", "osv-scanner", "trivy"}
    assert data["network_used"] is False


def test_init_status_detect(capsys, tmp_path):
    code, out, _ = run(capsys, "status", str(tmp_path))
    assert code == 1
    code, out, _ = run(capsys, "init", str(tmp_path))
    assert code == 0 and json.loads(out)["status"] == "initialized"
    code, out, _ = run(capsys, "init", str(tmp_path))
    assert json.loads(out)["status"] == "already_initialized"
    code, out, _ = run(capsys, "status", str(tmp_path))
    assert code == 0 and "Latest scan: none" in out
    code, out, _ = run(capsys, "detect", str(tmp_path))
    assert json.loads(out)["detected"] == ["generic"]


def test_missing_directory_is_clean_error(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "missing"))
    assert code == 2 and "Not an existing directory" in err


def test_malformed_config_reported(capsys, tmp_path):
    (tmp_path / ".uds").mkdir()
    (tmp_path / ".uds" / "config.toml").write_text("[broken", encoding="utf-8")
    code, _, err = run(capsys, "scan", str(tmp_path))
    assert code == 2 and "Could not parse" in err


def test_scan_without_any_scanner_is_not_success(capsys, tmp_path, monkeypatch):
    from universal_dev_security.scanners import base
    monkeypatch.setattr(base, "find_executable", lambda tool, names: (None, None))
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(tmp_path), "--json")
    data = json.loads(out)
    assert code == 2
    assert data["overall_status"] == "not_scanned"
    assert Path(data["reports"]["html"]).is_file()


@pytest.mark.skipif(find_gitleaks() is None, reason="Gitleaks is not installed")
def test_end_to_end_scan_history_compare_and_report(capsys, tmp_path):
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(tmp_path), "--tool", "gitleaks", "--json", "--format", "json,html,sarif")
    first = json.loads(out)
    assert code == 0 and first["overall_status"] == "clean"
    assert set(first["reports"]) == {"json", "html", "sarif"}

    secret = "Zq8r" + "T2vLx9Wm4KpB7nYs3DfH6jQcAb9"
    (tmp_path / "settings.py").write_text(f'client_secret = "{secret}"\n', encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(tmp_path), "--tool", "gitleaks", "--json", "--fail-on", "high")
    second = json.loads(out)
    assert code == 1
    assert second["overall_status"] == "findings"
    assert second["comparison"]["new"] == 1

    for report in Path(second["reports"]["json"]).parent.iterdir():
        assert secret not in report.read_text(encoding="utf-8")
    for entry in (tmp_path / ".uds" / "history").iterdir():
        assert secret not in entry.read_text(encoding="utf-8")

    code, out, _ = run(capsys, "history", str(tmp_path), "--json")
    assert len(json.loads(out)) == 2
    code, out, _ = run(capsys, "compare", str(tmp_path), "--json")
    assert len(json.loads(out)["new"]) == 1
    code, out, _ = run(capsys, "report", str(tmp_path), "--scan", "previous")
    assert code == 0
    code, out, _ = run(capsys, "dashboard", str(tmp_path))
    assert code == 0 and out.strip().endswith("security-report.html")


def test_policy_check_command(capsys, tmp_path):
    code, out, _ = run(capsys, "policy", "check", str(tmp_path), "--command", "git push origin main")
    assert code == 1 and json.loads(out)["decision"] == "ask"
    code, out, _ = run(capsys, "policy", "check", str(tmp_path), "--command", "git commit --no-verify -m x")
    assert code == 2 and json.loads(out)["decision"] == "deny"
    code, out, _ = run(capsys, "policy", "check", str(tmp_path), "--command", "pytest -q")
    assert code == 0
    code, out, _ = run(capsys, "policy", "show", str(tmp_path))
    assert any(r["rule_id"] == "git-push" for r in json.loads(out)["global_command_rules"])


def test_compare_invalid_id(capsys, tmp_path):
    code, _, err = run(capsys, "compare", str(tmp_path), "--base", "../../x")
    assert code == 2
