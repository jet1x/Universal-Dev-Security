"""Claude Code, generic agent, GitHub and VS Code integration tests."""
import json
import os
import re

import pytest

from universal_dev_security.cli import main
from universal_dev_security.integrations import agents, claude_code, github, vscode
from universal_dev_security.recovery import RecoveryManager

from fakes import FAKE_AWS_KEY


def hook(tool, tool_input, cwd):
    return claude_code.handle_hook({"hook_event_name": "PreToolUse", "tool_name": tool,
                                    "tool_input": tool_input, "cwd": str(cwd)})


@pytest.fixture(autouse=True)
def no_claude_env(monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)


# -- Claude Code hook runtime -------------------------------------------------------

def test_hook_asks_for_git_push(tmp_path):
    out = hook("Bash", {"command": "git push origin main"}, tmp_path)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_hook_denies_hook_bypass_and_powershell_is_covered(tmp_path):
    assert hook("Bash", {"command": "git commit --no-verify -m x"}, tmp_path)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert hook("PowerShell", {"command": "git push"}, tmp_path)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_never_auto_approves(tmp_path):
    assert hook("Bash", {"command": "pytest -q"}, tmp_path) is None
    assert hook("Write", {"file_path": str(tmp_path / "a.py"), "content": "x = 1\n"}, tmp_path) is None
    assert hook("Glob", {"pattern": "*"}, tmp_path) is None


def test_hook_denies_secret_writes_and_edits_without_echoing(tmp_path):
    for tool, data in (("Write", {"file_path": "cfg.py", "content": f"K='{FAKE_AWS_KEY}'"}),
                       ("Edit", {"file_path": "cfg.py", "old_string": "a", "new_string": f"K='{FAKE_AWS_KEY}'"}),
                       ("MultiEdit", {"file_path": "cfg.py", "edits": [{"old_string": "a", "new_string": FAKE_AWS_KEY}]})):
        out = hook(tool, data, tmp_path)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny", tool
        assert FAKE_AWS_KEY not in json.dumps(out)


def test_hook_protects_security_configuration(tmp_path):
    out = hook("Edit", {"file_path": str(tmp_path / ".claude" / "settings.json"), "old_string": "a", "new_string": "b"}, tmp_path)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    out = hook("Read", {"file_path": str(tmp_path / ".env")}, tmp_path)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_uses_project_config_restrictions(tmp_path):
    (tmp_path / ".uds").mkdir()
    (tmp_path / ".uds" / "config.toml").write_text("[policy]\ndeny_command_patterns = ['terraform apply']\n", encoding="utf-8")
    assert hook("Bash", {"command": "terraform apply"}, tmp_path)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_fails_closed(tmp_path, monkeypatch):
    assert json.loads(claude_code.run_hook("{not json")[1])["hookSpecificOutput"]["permissionDecision"] == "ask"
    monkeypatch.setattr(claude_code, "PolicyEngine", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    code, output = claude_code.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(tmp_path)}))
    assert code == 0 and json.loads(output)["hookSpecificOutput"]["permissionDecision"] == "ask"
    (tmp_path / ".uds").mkdir()
    (tmp_path / ".uds" / "config.toml").write_text("[broken", encoding="utf-8")
    monkeypatch.undo()
    out = hook("Bash", {"command": "ls"}, tmp_path)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_hook_cli_entry_point(tmp_path, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                                             "tool_input": {"command": "git push"}, "cwd": str(tmp_path)})))
    assert main(["hook", "claude-code"]) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "ask"


# -- Claude Code installation -------------------------------------------------------

def test_install_is_dry_run_by_default(tmp_path):
    result = claude_code.install(tmp_path)
    assert result["applied"] is False and result["changes"][0]["action"] == "create"
    assert not (tmp_path / ".claude").exists()


def test_install_merges_existing_settings_and_is_idempotent(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    user = {"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-hook"}]}]},
            "permissions": {"allow": ["Bash(npm test)"]}}
    settings.write_text(json.dumps(user), encoding="utf-8")
    result = claude_code.install(tmp_path, apply=True)
    assert result["applied"] and result["checkpoint"]
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["model"] == "opus"
    commands = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]]
    assert "my-hook" in commands and "uds hook claude-code" in commands
    assert data["permissions"]["allow"] == ["Bash(npm test)"]
    assert "Bash(git push:*)" in data["permissions"]["ask"]
    assert claude_code.install(tmp_path, apply=True)["changes"] == []  # idempotent

    claude_code.install(tmp_path, apply=True, remove=True)
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data == user  # only UDS-owned entries removed


def test_install_rollback_restores_original(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text('{"model": "x"}', encoding="utf-8")
    checkpoint = claude_code.install(tmp_path, apply=True)["checkpoint"]
    assert RecoveryManager(tmp_path).restore(checkpoint)["status"] == "restored"
    assert settings.read_text(encoding="utf-8") == '{"model": "x"}'


def test_install_refuses_invalid_json(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text("{oops", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        claude_code.install(tmp_path, apply=True)
    assert settings.read_text(encoding="utf-8") == "{oops"


def test_python_path_command_is_quoted():
    command = claude_code.hook_command(True)
    assert command.startswith('"') and command.endswith("-m universal_dev_security hook claude-code")


# -- generic agent guard ------------------------------------------------------------

def test_guard_protocol(tmp_path):
    code, data = agents.guard(json.dumps({"action": "shell", "command": "git push"}), str(tmp_path))
    assert code == 1 and data["decision"] == "ask"
    code, data = agents.guard(json.dumps({"action": "shell", "command": "ls"}), str(tmp_path))
    assert code == 0 and data["decision"] == "allow"
    code, data = agents.guard(json.dumps({"action": "write_file", "path": "a.py", "content": FAKE_AWS_KEY}), str(tmp_path))
    assert code == 2 and FAKE_AWS_KEY not in json.dumps(data)
    code, data = agents.guard("not json", str(tmp_path))
    assert code == 3 and data["decision"] == "deny"
    code, data = agents.guard(json.dumps({"action": "fly"}), str(tmp_path))
    assert code == 3


# -- GitHub workflow ----------------------------------------------------------------

def test_github_workflow_is_least_privilege_and_verified(tmp_path):
    result = github.install(tmp_path, apply=True)
    text = (tmp_path / github.WORKFLOW_PATH).read_text(encoding="utf-8")
    assert result["applied"]
    assert "permissions:\n  contents: read" in text
    assert "security-events: write" in text
    assert "contents: write" not in text and "pull-requests: write" not in text
    assert text.count("sha256sum -c -") == 3
    assert "persist-credentials: false" in text
    assert "git push" not in text
    assert "--fail-on high" in text and "upload-sarif" in text
    assert not re.search(r"__[A-Z_]+__", text)  # all placeholders substituted


def test_github_workflow_is_valid_yaml_if_pyyaml_available(tmp_path):
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(github.render_workflow())
    assert "uds-scan" in data["jobs"]


def test_github_refuses_foreign_workflow_and_bad_input(tmp_path):
    path = tmp_path / github.WORKFLOW_PATH
    path.parent.mkdir(parents=True)
    path.write_text("name: mine\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not generated by UDS"):
        github.install(tmp_path, apply=True)
    for kwargs in ({"branch": "main; rm -rf /"}, {"fail_on": "everything"}, {"uds_spec": 'x" && curl evil'},
                   {"gitleaks": "latest"}):
        with pytest.raises(ValueError):
            github.render_workflow(**kwargs)


# -- VS Code ------------------------------------------------------------------------

def test_vscode_tasks_merge_and_jsonc_refusal(tmp_path):
    tasks = tmp_path / ".vscode" / "tasks.json"
    tasks.parent.mkdir()
    tasks.write_text(json.dumps({"version": "2.0.0", "tasks": [{"label": "build", "command": "make"}]}), encoding="utf-8")
    vscode.install(tmp_path, apply=True)
    labels = [t["label"] for t in json.loads(tasks.read_text(encoding="utf-8"))["tasks"]]
    assert labels[0] == "build" and "UDS: Security scan" in labels
    vscode.install(tmp_path, apply=True, remove=True)
    assert [t["label"] for t in json.loads(tasks.read_text(encoding="utf-8"))["tasks"]] == ["build"]
    tasks.write_text('{ // comment\n "tasks": [] }', encoding="utf-8")
    with pytest.raises(ValueError, match="comments"):
        vscode.install(tmp_path, apply=True)


def test_integrate_cli_dry_run(tmp_path, capsys):
    assert main(["integrate", "github", str(tmp_path)]) == 0
    assert "Dry run only" in capsys.readouterr().out
    assert not (tmp_path / ".github").exists()
