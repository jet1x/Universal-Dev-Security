"""Git protection tests using real temporary Git repositories."""
import os
import shutil
import subprocess
import sys

import pytest

from universal_dev_security import gitguard
from universal_dev_security.recovery import RecoveryManager
from universal_dev_security.scanners import base

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git is not installed")

SECRET_LINE = 'client_secret = "' + "Zq8rT2vLx9Wm4KpB7nYs3DfH6jQcAb9" + '"\n'


def git(repo, *args, check=True):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=check)


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "UDS Test")
    git(path, "config", "core.autocrlf", "false")
    (path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    git(path, "add", "app.py")
    git(path, "commit", "-q", "-m", "init", "--no-verify")
    return path


@pytest.fixture(params=["gitleaks", "builtin"])
def engine(request, monkeypatch):
    if request.param == "builtin":
        monkeypatch.setattr(base, "find_executable", lambda tool, names: (None, None))
    elif base.find_executable("gitleaks", ("gitleaks",))[0] is None:
        pytest.skip("Gitleaks is not installed")
    return request.param


def test_pre_commit_blocks_staged_secret(repo, engine):
    (repo / "settings.py").write_text(SECRET_LINE, encoding="utf-8")
    git(repo, "add", "settings.py")
    code, message = gitguard.pre_commit(repo)
    assert code == 1
    assert "settings.py" in message and "Zq8rT2vLx9" not in message


def test_pre_commit_allows_clean_changes(repo, engine):
    (repo / "util.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    git(repo, "add", "util.py")
    assert gitguard.pre_commit(repo)[0] == 0


def test_pre_push_blocks_secret_in_outgoing_commit(repo, engine):
    base_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "settings.py").write_text(SECRET_LINE, encoding="utf-8")
    git(repo, "add", "settings.py")
    git(repo, "commit", "-q", "-m", "oops", "--no-verify")
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    code, message = gitguard.pre_push(repo, "origin", f"refs/heads/main {head} refs/heads/main {base_sha}\n")
    assert code == 1 and "outgoing commits" in message
    zero = "0" * 40
    code, _ = gitguard.pre_push(repo, "origin", f"refs/heads/main {head} refs/heads/main {zero}\n")
    assert code == 1  # new branch: all commits not on any remote are scanned
    assert gitguard.pre_push(repo, "origin", f"(delete) {zero} refs/heads/old {head}\n")[0] == 0


def test_pre_push_rejects_malformed_input(repo):
    assert gitguard.pre_push(repo, "origin", "refs/heads/main notasha refs/heads/main alsonot\n")[0] == 1
    assert gitguard.pre_push(repo, "origin; rm -rf /", "")[0] == 1


def test_install_hooks_dry_run_apply_status_uninstall(repo):
    plan = gitguard.install_hooks(repo)
    assert plan["applied"] is False and not (repo / ".git" / "hooks" / "pre-commit").exists()
    result = gitguard.install_hooks(repo, apply=True, python=sys.executable)
    assert result["applied"]
    script = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert gitguard.HOOK_MARKER in script and "exit 1" in script
    if os.name != "nt":
        assert os.access(repo / ".git" / "hooks" / "pre-commit", os.X_OK)
    status = gitguard.hooks_status(repo)
    assert all(h["state"] == "uds" for h in status["hooks"].values())
    gitguard.install_hooks(repo, apply=True, uninstall=True)
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_existing_foreign_hook_is_never_overwritten(repo):
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    result = gitguard.install_hooks(repo, apply=True)
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert [c["hook"] for c in result["conflicts"]] == ["pre-commit"]
    assert (repo / ".git" / "hooks" / "pre-push").exists()


def test_core_hooks_path_is_respected(repo):
    git(repo, "config", "core.hooksPath", ".husky")
    with pytest.raises(gitguard.GitError, match="core.hooksPath"):
        gitguard.install_hooks(repo, apply=True)


def test_hook_script_rejects_unsafe_interpreter_path():
    script = gitguard.hook_script("pre-commit", python='C:/x"; rm -rf ~; echo "')
    assert "rm -rf" not in script
    assert "UDS_PY" not in script


@pytest.mark.skipif(base.find_executable("gitleaks", ("gitleaks",))[0] is None, reason="Gitleaks is not installed")
def test_installed_hook_blocks_real_commit_end_to_end(repo):
    gitguard.install_hooks(repo, apply=True, python=sys.executable)
    (repo / "settings.py").write_text(SECRET_LINE, encoding="utf-8")
    git(repo, "add", "settings.py")
    blocked = git(repo, "commit", "-m", "should be blocked", check=False)
    assert blocked.returncode != 0, blocked.stderr
    assert "potential secret" in blocked.stderr
    git(repo, "rm", "--cached", "-q", "settings.py")
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    git(repo, "add", "ok.py")
    allowed = git(repo, "commit", "-m", "fine", check=False)
    assert allowed.returncode == 0, allowed.stderr


def test_hook_install_is_recoverable(repo):
    result = gitguard.install_hooks(repo, apply=True)
    restore = RecoveryManager(repo).restore(result["checkpoint"])
    assert restore["status"] == "restored"
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_cli_hooks_embed_interpreter_by_default(repo, capsys):
    # Regression (found while writing the getting-started guide): hooks that relied only on
    # `uds` from PATH blocked every commit made outside the activated virtual environment.
    from universal_dev_security.cli import main
    assert main(["hooks", "install", str(repo), "--apply"]) == 0
    script = (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "UDS_PY=" in script and "command -v uds" in script  # interpreter first, PATH fallback
    main(["hooks", "uninstall", str(repo), "--apply"])
    assert main(["hooks", "install", str(repo), "--apply", "--path-only"]) == 0
    assert "UDS_PY=" not in (repo / ".git" / "hooks" / "pre-commit").read_text(encoding="utf-8")
