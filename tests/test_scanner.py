"""Scanner adapter tests: discovery, state handling, sanitization, normalization."""
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from universal_dev_security import scanner as legacy
from universal_dev_security.findings import ScanStatus, Severity
from universal_dev_security.projectfiles import build_inventory
from universal_dev_security.scanners import base, get_scanner
from universal_dev_security.scanners import gitleaks as gl
from universal_dev_security.scanners import osv, semgrep, trivy
from universal_dev_security.scanners.base import ScanOptions

from fakes import FAKE_HIGH_ENTROPY

SECRET = "DO_NOT_LEAK_" + "THIS_SECRET_VALUE"


@pytest.fixture
def fake_tool(monkeypatch, tmp_path):
    """Pretend every scanner is installed at a real file and reports a given version."""
    exe = tmp_path / ("tool.exe" if os.name == "nt" else "tool")
    exe.write_bytes(b"")
    monkeypatch.setattr(base, "find_executable", lambda tool, names: (str(exe), None))
    monkeypatch.setattr(base.ScannerAdapter, "detect_version", lambda self, e, c: "99.0.0")
    return exe


def project(tmp_path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def run(adapter_name, root, options=None):
    adapter = get_scanner(adapter_name)
    return adapter.scan(root, build_inventory(root), options or ScanOptions())


# -- discovery and states -----------------------------------------------------

def test_not_installed_is_reported_not_success(monkeypatch, tmp_path):
    monkeypatch.setattr(base, "find_executable", lambda tool, names: (None, None))
    result = run("gitleaks", project(tmp_path, {"a.py": "x=1"}))
    assert result.status is ScanStatus.NOT_INSTALLED
    assert not result.status.executed


def test_unsupported_version_is_skipped(monkeypatch, fake_tool, tmp_path):
    monkeypatch.setattr(base.ScannerAdapter, "detect_version", lambda self, e, c: "8.10.0")
    result = run("gitleaks", project(tmp_path, {"a.py": "x=1"}))
    assert result.status is ScanStatus.SKIPPED
    assert result.reason == "unsupported_version"


def test_unknown_version_is_skipped(monkeypatch, fake_tool, tmp_path):
    monkeypatch.setattr(base.ScannerAdapter, "detect_version", lambda self, e, c: None)
    assert run("gitleaks", project(tmp_path, {"a.py": "x=1"})).status is ScanStatus.SKIPPED


def test_not_applicable_without_relevant_files(fake_tool, tmp_path):
    root = project(tmp_path, {"README.md": "# hi"})
    assert run("semgrep", root).status is ScanStatus.NOT_APPLICABLE
    assert run("osv-scanner", root).status is ScanStatus.NOT_APPLICABLE
    assert run("trivy", root).status is ScanStatus.NOT_APPLICABLE


def test_osv_requires_network_approval(fake_tool, monkeypatch, tmp_path):
    called = Mock()
    monkeypatch.setattr(osv, "run_tool", called)
    root = project(tmp_path, {"requirements.txt": "jinja2==2.4.1\n"})
    result = run("osv-scanner", root)
    assert result.status is ScanStatus.SKIPPED
    assert result.reason == "network_not_approved"
    called.assert_not_called()


def test_timeout_is_error(fake_tool, monkeypatch, tmp_path):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("gitleaks", 1)
    monkeypatch.setattr(gl, "run_tool", boom)
    result = run("gitleaks", project(tmp_path, {"a.py": "x"}))
    assert result.status is ScanStatus.ERROR and result.reason == "timeout"


def test_unexpected_exit_code_is_error_and_output_suppressed(fake_tool, monkeypatch, tmp_path):
    monkeypatch.setattr(gl, "run_tool", lambda *a, **k: Mock(returncode=126, stdout=SECRET, stderr=SECRET))
    result = run("gitleaks", project(tmp_path, {"a.py": "x"}))
    assert result.status is ScanStatus.ERROR
    assert SECRET not in json.dumps(result.to_dict())


def test_env_override_must_be_real_file(monkeypatch, tmp_path):
    monkeypatch.setenv("UDS_TRIVY_PATH", str(tmp_path / "missing.exe"))
    path, note = base.find_executable("trivy", ("trivy",))
    assert path is None and "UDS_TRIVY_PATH" in note
    real = tmp_path / "trivy.exe"
    real.write_bytes(b"")
    monkeypatch.setenv("UDS_TRIVY_PATH", str(real))
    assert base.find_executable("trivy", ("trivy",))[0] == str(real.resolve())


@pytest.mark.skipif(os.name != "nt", reason="batch-file refusal is Windows-specific")
def test_batch_wrappers_are_refused(monkeypatch, tmp_path):
    wrapper = tmp_path / "semgrep.cmd"
    wrapper.write_text("@echo off", encoding="utf-8")
    monkeypatch.setattr(base.shutil, "which", lambda name: str(wrapper))
    monkeypatch.setattr(base, "_candidate_dirs", lambda tool: [])
    path, note = base.find_executable("semgrep", ("semgrep",))
    assert path is None and "batch" in note.lower()
    with pytest.raises(base.ScannerExecutionError):
        base.run_tool([str(wrapper), "--version"], cwd=tmp_path, timeout=5)


def test_run_tool_rejects_bad_arguments(tmp_path):
    with pytest.raises(base.ScannerExecutionError):
        base.run_tool([], cwd=tmp_path, timeout=5)
    with pytest.raises(base.ScannerExecutionError):
        base.run_tool([str(tmp_path / "nope.exe")], cwd=tmp_path, timeout=5)


def test_parse_version_variants():
    assert base.parse_version("v8.30.1") == (8, 30, 1)
    assert base.parse_version("Version: 0.58") == (0, 58, 0)
    assert base.parse_version("osv-scanner version: 2.0.1\ncommit: abc") == (2, 0, 1)
    assert base.parse_version("garbage") is None


def test_relative_path_never_leaks_outside_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    assert base.relative_path(str(root / "a" / "b.py"), root) == "a/b.py"
    assert base.relative_path(str(tmp_path / "elsewhere" / "secret.txt"), root) == "secret.txt"
    assert base.relative_path("./x/y.js", root) == "x/y.js"


# -- Gitleaks ---------------------------------------------------------------------

def test_gitleaks_sanitizes_secret_values(fake_tool, monkeypatch, tmp_path):
    def fake_run(command, **kwargs):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text(json.dumps([{
            "RuleID": "generic-api-key", "Description": "Generic key", "File": "config.py",
            "StartLine": 4, "EndLine": 4, "Commit": "abc123", "Secret": SECRET, "Match": f"token={SECRET}",
            "Line": f"token={SECRET}", "Fingerprint": "config.py:generic-api-key:4",
        }]), encoding="utf-8")
        assert "--redact" in command
        return Mock(returncode=1, stdout="", stderr=SECRET)

    monkeypatch.setattr(gl, "run_tool", fake_run)
    result = run("gitleaks", project(tmp_path, {"config.py": "x"}))
    rendered = json.dumps(result.to_dict())
    assert result.status is ScanStatus.FINDINGS
    assert result.findings[0].severity is Severity.UNCLASSIFIED
    assert result.findings[0].file == "config.py"
    assert SECRET not in rendered


def test_gitleaks_respects_project_config(fake_tool, monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gl, "run_tool", fake_run)
    root = project(tmp_path, {".gitleaks.toml": "", "a.py": "x"})
    assert run("gitleaks", root).status is ScanStatus.CLEAN
    assert "--config" not in seen["command"]
    root2 = project(tmp_path / "b", {"a.py": "x"})
    run("gitleaks", root2)
    assert "--config" in seen["command"]


def test_gitleaks_exit_one_without_report_is_error(fake_tool, monkeypatch, tmp_path):
    monkeypatch.setattr(gl, "run_tool", lambda *a, **k: Mock(returncode=1, stdout="", stderr=""))
    assert run("gitleaks", project(tmp_path, {"a.py": "x"})).status is ScanStatus.ERROR


def test_gitleaks_exclusion_config_is_valid_toml():
    import tomllib
    data = tomllib.loads(gl.build_exclusion_config(["custom/dir"]))
    assert data["extend"]["useDefault"] is True
    pattern = data["allowlist"]["paths"][0]
    import re
    assert re.search(pattern, "node_modules/x/y.js")
    assert re.search(pattern, ".uds/backups/1/file.py")
    assert re.search(pattern, "custom/dir/a.py")
    assert not re.search(pattern, "src/app.py")
    assert not re.search(pattern, "dist/bundle.js")  # build output is still secret-scanned


def test_legacy_api_still_works(monkeypatch, tmp_path):
    monkeypatch.setattr(base, "find_executable", lambda tool, names: (None, None))
    result = legacy.scan_with_gitleaks(tmp_path)
    assert result["status"] == "not_installed" and result["finding_count"] == 0


@pytest.mark.skipif(legacy.find_gitleaks() is None, reason="Gitleaks is not installed")
def test_real_gitleaks_detects_fake_secret_without_leaking_it(tmp_path):
    """Integration test against the installed Gitleaks binary."""
    secret = FAKE_HIGH_ENTROPY + "Ab9"
    root = project(tmp_path, {
        "src/settings.py": f'client_secret = "{secret}"\n',
        "node_modules/pkg/index.js": f'const client_secret = "{secret}";\n',
        ".venv/lib/x.py": f'client_secret = "{secret}"\n',
    })
    result = run("gitleaks", root)
    assert result.status is ScanStatus.FINDINGS, result.message
    assert [f.file for f in result.findings] == ["src/settings.py"]
    assert result.findings[0].start_line == 1
    assert secret not in json.dumps(result.to_dict())


@pytest.mark.skipif(legacy.find_gitleaks() is None, reason="Gitleaks is not installed")
def test_real_gitleaks_clean_project(tmp_path):
    result = run("gitleaks", project(tmp_path, {"main.py": "print('hello')\n"}))
    assert result.status is ScanStatus.CLEAN
    assert result.version and base.parse_version(result.version) >= (8, 19, 0)


# -- Semgrep ------------------------------------------------------------------------

SEMGREP_OUTPUT = {
    "version": "1.95.0",
    "results": [
        {"check_id": "python.lang.security.audit.eval-detected.eval-detected", "path": "app/main.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 20},
         "extra": {"message": f"Detected eval; value {SECRET}", "severity": "WARNING",
                   "lines": f"eval(user_input)  # {SECRET}",
                   "metadata": {"cwe": ["CWE-95: Eval Injection"], "references": ["https://owasp.org/x"]}}},
        {"check_id": "custom.rule.crit", "path": "app/x.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "bad", "severity": "CRITICAL", "metadata": {}}},
        {"check_id": "custom.rule.weird", "path": "app/y.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "odd", "severity": "EXPERIMENT", "metadata": {}}},
    ],
    "errors": [],
}


def test_semgrep_normalization_and_documented_severity_mapping(tmp_path):
    findings = semgrep.normalize(SEMGREP_OUTPUT, tmp_path)
    assert [f.severity for f in findings] == [Severity.MEDIUM, Severity.CRITICAL, Severity.UNCLASSIFIED]
    assert findings[0].scanner_severity == "WARNING"
    assert findings[0].severity_source == "scanner"
    assert findings[2].severity_source == "none"
    assert findings[0].start_line == 3
    assert "https://owasp.org/x" in findings[0].references
    rendered = json.dumps([f.to_dict() for f in findings])
    assert "eval(user_input)" not in rendered  # matched source lines never copied


def test_semgrep_command_is_private_and_never_uses_auto(fake_tool, monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"], seen["env"] = command, kwargs.get("env_overrides")
        return Mock(returncode=0, stdout=json.dumps(SEMGREP_OUTPUT), stderr="")

    monkeypatch.setattr(semgrep, "run_tool", fake_run)
    root = project(tmp_path, {"app/main.py": "eval(x)\n"})
    result = run("semgrep", root, ScanOptions(semgrep_configs=["auto", "p/python"]))
    assert result.status is ScanStatus.FINDINGS
    assert "--metrics=off" in seen["command"]
    assert "auto" not in seen["command"]
    assert seen["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert "shell" not in json.dumps(seen["command"])


def test_semgrep_error_and_bad_json(fake_tool, monkeypatch, tmp_path):
    root = project(tmp_path, {"a.py": "x"})
    monkeypatch.setattr(semgrep, "run_tool", lambda *a, **k: Mock(returncode=2, stdout="", stderr=""))
    assert run("semgrep", root).status is ScanStatus.ERROR
    monkeypatch.setattr(semgrep, "run_tool", lambda *a, **k: Mock(returncode=0, stdout="not json", stderr=""))
    assert run("semgrep", root).status is ScanStatus.ERROR
    monkeypatch.setattr(semgrep, "run_tool", lambda *a, **k: Mock(returncode=0, stdout='{"results": []}', stderr=""))
    assert run("semgrep", root).status is ScanStatus.CLEAN


# -- OSV-Scanner --------------------------------------------------------------------

def osv_output(root: Path, max_severity="9.8", db_severity=None):
    return {"results": [{
        "source": {"path": str(root / "requirements.txt"), "type": "lockfile"},
        "packages": [{
            "package": {"name": "jinja2", "version": "2.4.1", "ecosystem": "PyPI"},
            "vulnerabilities": [
                {"id": "GHSA-462w-v97r-4m45", "summary": "Jinja2 sandbox escape", "aliases": ["CVE-2019-10906"],
                 "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
                 "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-462w-v97r-4m45"}],
                 "database_specific": {"severity": db_severity} if db_severity else {}},
                {"id": "PYSEC-2019-217", "summary": "dup", "aliases": ["CVE-2019-10906"]},
            ],
            "groups": [{"ids": ["GHSA-462w-v97r-4m45", "PYSEC-2019-217"], "aliases": ["CVE-2019-10906"],
                        "max_severity": max_severity}],
        }],
    }]}


def test_osv_normalization_groups_aliases_and_uses_cvss_scale(tmp_path):
    findings = osv.normalize(osv_output(tmp_path), tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GHSA-462w-v97r-4m45"
    assert f.severity is Severity.CRITICAL and f.severity_source == "cvss-qualitative-scale"
    assert f.file == "requirements.txt"
    assert f.fixed_version == "2.10.1"
    assert f.package == "jinja2" and f.installed_version == "2.4.1"


def test_osv_severity_fallbacks(tmp_path):
    assert osv.normalize(osv_output(tmp_path, "", "MODERATE"), tmp_path)[0].severity is Severity.MEDIUM
    unknown = osv.normalize(osv_output(tmp_path, "", None), tmp_path)[0]
    assert unknown.severity is Severity.UNCLASSIFIED and unknown.severity_source == "none"


def test_osv_command_versions_and_exit_codes(fake_tool, monkeypatch, tmp_path):
    adapter = get_scanner("osv-scanner")
    assert adapter.build_command("osv", "2.0.1", ScanOptions())[1:3] == ["scan", "source"]
    assert "scan" not in adapter.build_command("osv", "1.9.0", ScanOptions())
    root = project(tmp_path, {"requirements.txt": "jinja2==2.4.1\n"})
    allow = ScanOptions(allow_network=True)
    monkeypatch.setattr(osv, "run_tool", lambda *a, **k: Mock(returncode=128, stdout="", stderr=""))
    assert run("osv-scanner", root, allow).status is ScanStatus.CLEAN
    monkeypatch.setattr(osv, "run_tool", lambda *a, **k: Mock(returncode=1, stdout=json.dumps(osv_output(root)), stderr=""))
    assert run("osv-scanner", root, allow).status is ScanStatus.FINDINGS
    monkeypatch.setattr(osv, "run_tool", lambda *a, **k: Mock(returncode=127, stdout="", stderr=""))
    assert run("osv-scanner", root, allow).status is ScanStatus.ERROR


# -- Trivy ----------------------------------------------------------------------------

TRIVY_OUTPUT = {
    "SchemaVersion": 2,
    "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2019-10906", "PkgName": "jinja2", "InstalledVersion": "2.4.1",
             "FixedVersion": "2.10.1", "Severity": "HIGH", "Title": "sandbox escape",
             "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-10906"},
            {"VulnerabilityID": "CVE-2000-0001", "PkgName": "x", "InstalledVersion": "1", "Severity": "UNKNOWN"},
        ]},
        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile", "Misconfigurations": [
            {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
             "Status": "FAIL", "Message": "Specify at least 1 USER command", "Resolution": "Add 'USER <non root user name>'",
             "CauseMetadata": {"StartLine": 1, "EndLine": 3, "Code": {"Lines": [{"Content": SECRET}]}}},
            {"ID": "DS001", "AVDID": "AVD-DS-0001", "Title": "ok", "Severity": "MEDIUM", "Status": "PASS"},
        ]},
    ],
}


def test_trivy_normalization(tmp_path):
    findings = trivy.normalize(TRIVY_OUTPUT, tmp_path)
    assert len(findings) == 3
    vuln, unknown, misconf = findings
    assert vuln.severity is Severity.HIGH and vuln.category.value == "dependency"
    assert unknown.severity is Severity.UNCLASSIFIED
    assert misconf.category.value == "configuration" and misconf.start_line == 1
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_trivy_command_disables_secret_scanner(fake_tool, monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        Path(command[command.index("--output") + 1]).write_text(json.dumps(TRIVY_OUTPUT), encoding="utf-8")
        return Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(trivy, "run_tool", fake_run)
    result = run("trivy", project(tmp_path, {"Dockerfile": "FROM alpine\n"}))
    assert result.status is ScanStatus.FINDINGS
    scanners_arg = seen["command"][seen["command"].index("--scanners") + 1]
    assert "secret" not in scanners_arg
