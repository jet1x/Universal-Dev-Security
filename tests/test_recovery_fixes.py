"""Recovery engine, automatic fixes, testing engine and update checks."""
import json
import sys

import pytest

from universal_dev_security import updates
from universal_dev_security.config import ProjectConfig
from universal_dev_security.fixes import apply_fixes, manual_recommendations, plan_fixes
from universal_dev_security.recovery import RecoveryError, RecoveryManager, resolve_inside, safe_write
from universal_dev_security.testing import detect_test_command, run_tests

from fakes import FAKE_HIGH_ENTROPY


# -- recovery ---------------------------------------------------------------------

def test_checkpoint_restore_roundtrip(tmp_path):
    (tmp_path / "a.txt").write_text("original", encoding="utf-8")
    manager = RecoveryManager(tmp_path)
    cp = manager.create("test", ["a.txt", "new.txt"])
    safe_write(tmp_path, "a.txt", "changed")
    safe_write(tmp_path, "new.txt", "created by uds")
    manager.seal(cp)
    result = manager.restore(cp)
    assert result["status"] == "restored"
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "original"
    assert not (tmp_path / "new.txt").exists()
    assert manager.list()[0]["restored"] is True


def test_restore_preserves_later_user_changes(tmp_path):
    (tmp_path / "a.txt").write_text("original", encoding="utf-8")
    manager = RecoveryManager(tmp_path)
    cp = manager.create("test", ["a.txt"])
    safe_write(tmp_path, "a.txt", "uds change")
    manager.seal(cp)
    (tmp_path / "a.txt").write_text("user edited afterwards", encoding="utf-8")
    result = manager.restore(cp)
    assert result["status"] == "conflicts" and result["conflicts"] == ["a.txt"]
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "user edited afterwards"
    assert manager.restore(cp, force=True)["status"] == "restored"
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "original"


@pytest.mark.parametrize("bad", ["../outside.txt", "..\\outside.txt", "/etc/passwd", "C:\\Windows\\x", "a/../../x", ""])
def test_paths_outside_project_rejected(tmp_path, bad):
    with pytest.raises(RecoveryError):
        resolve_inside(tmp_path, bad)


def test_invalid_checkpoint_ids_rejected(tmp_path):
    with pytest.raises(RecoveryError):
        RecoveryManager(tmp_path).restore("../../etc")


def test_safe_write_is_atomic_and_leaves_no_temp_files(tmp_path):
    safe_write(tmp_path, "dir/file.txt", "content\n")
    assert (tmp_path / "dir" / "file.txt").read_text(encoding="utf-8") == "content\n"
    assert [p.name for p in (tmp_path / "dir").iterdir()] == ["file.txt"]


# -- fixes ------------------------------------------------------------------------

def test_gitignore_fix_appends_without_destroying_content(tmp_path):
    (tmp_path / ".gitignore").write_text("node_modules/\n.env\n", encoding="utf-8")
    result = apply_fixes(tmp_path, ProjectConfig(), run_test_suite=False)
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert result["status"] == "applied" and result["checkpoint"]
    assert text.startswith("node_modules/\n.env\n")
    assert text.count(".env\n") == 1 and "!.env.example" in text
    assert apply_fixes(tmp_path, ProjectConfig(), run_test_suite=False)["status"] == "nothing_to_do"


def test_medium_fix_requires_opt_in_and_never_copies_values(tmp_path):
    (tmp_path / ".env").write_text(f"API_TOKEN={FAKE_HIGH_ENTROPY}\nexport DB_URL=postgres://x\n# c\n", encoding="utf-8")
    apply_fixes(tmp_path, ProjectConfig(), run_test_suite=False)
    assert not (tmp_path / ".env.example").exists()
    apply_fixes(tmp_path, ProjectConfig(), run_test_suite=False, include_medium=True)
    example = (tmp_path / ".env.example").read_text(encoding="utf-8")
    assert "API_TOKEN=\n" in example and "DB_URL=\n" in example
    assert FAKE_HIGH_ENTROPY not in example and "postgres" not in example


def test_fix_disabled_by_config_requires_approval(tmp_path):
    config = ProjectConfig(allow_automatic_low_risk_fixes=False)
    assert apply_fixes(tmp_path, config, run_test_suite=False)["status"] == "approval_required"
    assert apply_fixes(tmp_path, config, run_test_suite=False, approved=True)["status"] == "applied"


def _pytest_project(tmp_path, test_body):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(test_body, encoding="utf-8")
    return ProjectConfig(test_command=[sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"])


def test_fix_rolls_back_when_tests_fail_after_change(tmp_path):
    # This test fails only once .gitignore contains the UDS block, simulating a breaking fix.
    config = _pytest_project(tmp_path, "from pathlib import Path\n"
                                       "def test_x():\n"
                                       "    p = Path(__file__).parents[1] / '.gitignore'\n"
                                       "    assert not p.exists() or 'Universal Dev Security' not in p.read_text()\n")
    result = apply_fixes(tmp_path, config)
    assert result["status"] == "rolled_back", result
    assert not (tmp_path / ".gitignore").exists()


def test_fix_not_applied_when_baseline_tests_fail(tmp_path):
    config = _pytest_project(tmp_path, "def test_x():\n    assert False\n")
    assert apply_fixes(tmp_path, config)["status"] == "baseline_tests_failing"
    assert not (tmp_path / ".gitignore").exists()


def test_fix_kept_when_tests_pass(tmp_path):
    config = _pytest_project(tmp_path, "def test_x():\n    assert True\n")
    result = apply_fixes(tmp_path, config)
    assert result["status"] == "applied" and result["tests"]["passed"] is True


def test_plan_and_manual_recommendations(tmp_path):
    assert plan_fixes(tmp_path)[0]["id"] == "gitignore-secrets"
    recs = manual_recommendations({"findings": [
        {"category": "dependency", "package": "jinja2", "installed_version": "2.4.1", "fixed_version": "2.10.1"},
        {"category": "secret", "file": "a.py"}]})
    assert {r["risk"] for r in recs} == {"high", "critical"}


# -- testing engine ---------------------------------------------------------------

def test_detect_test_commands(tmp_path):
    assert detect_test_command(tmp_path)[0] is None
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}), encoding="utf-8")
    assert detect_test_command(tmp_path)[0] is None
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "jest"}}), encoding="utf-8")
    assert detect_test_command(tmp_path)[0] == ["npm", "test", "--silent"]
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    assert detect_test_command(tmp_path)[0][1:] == ["-m", "pytest", "-q"]
    assert detect_test_command(tmp_path, ProjectConfig(test_command=["make", "check"]))[0] == ["make", "check"]


def test_run_tests_reports_real_results(tmp_path):
    config = _pytest_project(tmp_path, "def test_ok():\n    assert 1 == 1\n")
    assert run_tests(tmp_path, config)["status"] == "passed"
    assert run_tests(tmp_path, ProjectConfig(test_command=["definitely-not-a-command-xyz"]))["status"] == "error"
    assert run_tests(tmp_path / "missing" if False else tmp_path, ProjectConfig())["status"] in ("passed", "not_configured")


# -- updates ----------------------------------------------------------------------

def test_update_check_requires_explicit_source():
    assert updates.check_uds_update(None)["status"] == "source_not_configured"


def test_update_check_pypi_and_github(monkeypatch):
    monkeypatch.setattr(updates, "__version__", "1.0.0")
    assert updates.check_uds_update("pypi", fetch=lambda url: {"info": {"version": "1.1.0"}})["status"] == "update_available"
    assert updates.check_uds_update("pypi", fetch=lambda url: {"info": {"version": "1.0.0"}})["status"] == "up_to_date"
    assert updates.check_uds_update("github:owner/repo", fetch=lambda url: {"tag_name": "v0.9.0"})["status"] == "up_to_date"
    assert updates.check_uds_update("github:../../evil", fetch=lambda url: {})["status"] == "error"
    assert updates.check_uds_update("ftp://x", fetch=lambda url: {})["status"] == "error"


def test_prerelease_ordering():
    assert updates._version_tuple("1.0.0rc1") < updates._version_tuple("1.0.0")
    assert updates._version_tuple("0.9.0") < updates._version_tuple("1.0.0rc1")
