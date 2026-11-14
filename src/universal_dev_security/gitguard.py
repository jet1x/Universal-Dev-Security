"""Git protection: pre-commit and pre-push secret scanning hooks.

Local hooks are defense in depth — they can be bypassed with ``--no-verify``
(which the UDS policy denies for AI agents). Use CI scanning as well.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from universal_dev_security.integrations import apply_changes
from universal_dev_security.redaction import find_secrets
from universal_dev_security.scanners.base import ScannerExecutionError, run_tool
from universal_dev_security.scanners.gitleaks import GitleaksAdapter, build_exclusion_config

HOOK_MARKER = "UDS-MANAGED-HOOK"
HOOK_NAMES = ("pre-commit", "pre-push")
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_SAFE_SH_PATH = re.compile(r"^[A-Za-z0-9 _.:/\\()+-]+$")
MAX_STAGED_FILE_BYTES = 2 * 1024 * 1024


class GitError(RuntimeError):
    pass


def _git_executable() -> str:
    git = shutil.which("git")
    if not git:
        raise GitError("Git is not installed or not on PATH.")
    return git


def git(root: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return run_tool([_git_executable(), *args], cwd=root, timeout=timeout)
    except ScannerExecutionError as exc:
        raise GitError(str(exc)) from exc


def repo_root(path: Path) -> Path:
    completed = git(path, "rev-parse", "--show-toplevel")
    if completed.returncode != 0:
        raise GitError(f"Not a Git repository: {path}")
    return Path(completed.stdout.strip()).resolve()


def hooks_path_config(root: Path) -> str | None:
    completed = git(root, "config", "--get", "core.hooksPath")
    value = completed.stdout.strip()
    return value or None


def hooks_dir(root: Path) -> Path:
    completed = git(root, "rev-parse", "--git-path", "hooks")
    if completed.returncode != 0:
        raise GitError("Could not determine the Git hooks directory.")
    path = Path(completed.stdout.strip())
    return (root / path).resolve() if not path.is_absolute() else path.resolve()


def _sh_quote_path(path: str) -> str | None:
    if not _SAFE_SH_PATH.match(path):
        return None
    return '"' + path.replace("\\", "/") + '"'


def hook_script(hook: str, python: str | None = None) -> str:
    quoted = _sh_quote_path(python) if python else None
    lines = [
        "#!/bin/sh",
        f"# {HOOK_MARKER} v1 - installed by Universal Dev Security.",
        "# Remove with `uds hooks uninstall`. Do not edit: UDS may update this file.",
    ]
    if quoted:
        lines += [f"UDS_PY={quoted}",
                  'if [ -f "$UDS_PY" ]; then exec "$UDS_PY" -m universal_dev_security hook git-' + hook + ' "$@"; fi']
    lines += [
        "if command -v uds >/dev/null 2>&1; then exec uds hook git-" + hook + ' "$@"; fi',
        f'echo "UDS: the uds command was not found, so the {hook} security check cannot run. Blocking." >&2',
        'echo "UDS: reinstall UDS or run \'uds hooks uninstall\' to remove this hook." >&2',
        "exit 1",
    ]
    return "\n".join(lines) + "\n"


def _hook_relpaths(root: Path) -> dict[str, str]:
    directory = hooks_dir(root)
    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise GitError(f"The hooks directory {directory} is outside the repository; UDS will not modify it.") from exc
    return {hook: (relative / hook).as_posix() for hook in HOOK_NAMES}


def hooks_status(root: Path) -> dict[str, Any]:
    root = repo_root(root)
    custom = hooks_path_config(root)
    status: dict[str, Any] = {"repository": str(root), "core_hooks_path": custom, "hooks": {}}
    try:
        paths = _hook_relpaths(root)
    except GitError as exc:
        status["error"] = str(exc)
        return status
    for hook, relative in paths.items():
        path = root / relative
        if not path.exists():
            state = "missing"
        elif HOOK_MARKER in path.read_text(encoding="utf-8", errors="replace"):
            state = "uds"
        else:
            state = "foreign"
        status["hooks"][hook] = {"path": relative, "state": state}
    return status


def install_hooks(path: Path, *, apply: bool = False, uninstall: bool = False,
                  python: str | None = None) -> dict[str, Any]:
    root = repo_root(path)
    custom = hooks_path_config(root)
    if custom:
        raise GitError(
            f"core.hooksPath is set to {custom!r} (another hook manager is in use). UDS will not change it. "
            "Call `uds hook git-pre-commit` and `uds hook git-pre-push` from your existing hooks instead."
        )
    paths = _hook_relpaths(root)
    changes: dict[str, str | None] = {}
    conflicts = []
    for hook, relative in paths.items():
        target = root / relative
        existing = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else None
        if existing is not None and HOOK_MARKER not in existing:
            conflicts.append({"hook": hook, "path": relative,
                              "message": "An existing non-UDS hook is present and was left unchanged. "
                                         f"Add `uds hook git-{hook} \"$@\"` to it manually."})
            continue
        if uninstall:
            if existing is not None:
                changes[relative] = None
        else:
            changes[relative] = hook_script(hook, python)
    result = apply_changes(root, changes, "git hooks " + ("uninstall" if uninstall else "install"), apply)
    if result["applied"] and not uninstall and os.name != "nt":
        for relative in changes:
            p = root / relative
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    result["conflicts"] = conflicts
    result["repository"] = str(root)
    return result


# ---------------------------------------------------------------------------
# Hook runtime
# ---------------------------------------------------------------------------

def _gitleaks_git(root: Path, extra: list[str]) -> list[dict[str, Any]] | None:
    """Run `gitleaks git` and return sanitized findings, or None if Gitleaks is unavailable."""
    adapter = GitleaksAdapter()
    executable, _ = adapter.locate()
    if not executable or not adapter.is_compatible(adapter.detect_version(executable, root)):
        return None
    with tempfile.TemporaryDirectory(prefix="uds-hook-") as temp:
        report = Path(temp) / "report.json"
        command = [executable, "git", "--no-banner", "--redact", "--exit-code", "1",
                   "--report-format", "json", "--report-path", str(report)]
        if not (root / ".gitleaks.toml").is_file():
            config = Path(temp) / "uds.toml"
            config.write_text(build_exclusion_config([]), encoding="utf-8")
            command += ["--config", str(config)]
        completed = run_tool(command + extra + ["."], cwd=root, timeout=600)
        if completed.returncode not in (0, 1):
            raise GitError(f"Gitleaks failed with exit code {completed.returncode}; output suppressed.")
        if not report.is_file():
            return []
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    return [{"rule_id": str(i.get("RuleID")), "file": str(i.get("File", "")), "line": i.get("StartLine"),
             "commit": str(i.get("Commit") or "")[:12]} for i in data if isinstance(i, dict)]


def _builtin_staged_scan(root: Path) -> list[dict[str, Any]]:
    listing = git(root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    findings = []
    for name in [n for n in listing.stdout.split("\0") if n]:
        shown = git(root, "show", f":{name}")
        if shown.returncode != 0 or len(shown.stdout) > MAX_STAGED_FILE_BYTES or "\x00" in shown.stdout[:8000]:
            continue
        for match in find_secrets(shown.stdout):
            findings.append({"rule_id": match.rule_id, "file": name, "line": match.line, "commit": ""})
    return findings


def _builtin_range_scan(root: Path, rev_args: list[str]) -> list[dict[str, Any]]:
    log = git(root, "log", "-p", "--no-color", "--no-ext-diff", "--format=commit %H", *rev_args)
    findings, commit, file = [], "", ""
    added: list[str] = []

    def flush() -> None:
        if added:
            for match in find_secrets("\n".join(added)):
                findings.append({"rule_id": match.rule_id, "file": file, "line": None, "commit": commit[:12]})
        added.clear()

    for line in log.stdout.splitlines():
        if line.startswith("commit "):
            flush()
            commit = line.split(" ", 1)[1]
        elif line.startswith("+++ "):
            flush()
            file = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    flush()
    return findings


def _report(findings: list[dict[str, Any]], context: str, engine: str) -> str:
    lines = [f"UDS: {len(findings)} potential secret(s) found in {context} ({engine}). Blocked."]
    for f in findings[:50]:
        where = f["file"] + (f":{f['line']}" if f.get("line") else "") + (f" @ {f['commit']}" if f.get("commit") else "")
        lines.append(f"  - {f['rule_id']}: {where}")
    lines.append("UDS: remove the secret, rotate it if it was ever pushed, and use environment variables or a secret manager.")
    return "\n".join(lines)


def pre_commit(path: Path) -> tuple[int, str]:
    root = repo_root(path)
    findings = _gitleaks_git(root, ["--pre-commit", "--staged"])
    engine = "Gitleaks"
    if findings is None:
        findings, engine = _builtin_staged_scan(root), "UDS built-in patterns; install Gitleaks for full coverage"
    if findings:
        return 1, _report(findings, "staged changes", engine)
    return 0, f"UDS: no secrets detected in staged changes ({engine})."


def pre_push(path: Path, remote: str, stdin_text: str) -> tuple[int, str]:
    root = repo_root(path)
    if not _REMOTE_RE.match(remote or "origin"):
        return 1, "UDS: unexpected remote name; push blocked."
    all_findings: list[dict[str, Any]] = []
    engine = "Gitleaks"
    for raw in stdin_text.splitlines():
        parts = raw.split()
        if len(parts) != 4:
            continue
        _, local_sha, _, remote_sha = parts
        if not (_SHA_RE.match(local_sha) and _SHA_RE.match(remote_sha)):
            return 1, "UDS: unexpected pre-push input; push blocked."
        if set(local_sha) == {"0"}:
            continue  # branch deletion: nothing outgoing
        if set(remote_sha) == {"0"}:
            rev_args = [local_sha, "--not", f"--remotes={remote or 'origin'}"]
        else:
            rev_args = [f"{remote_sha}..{local_sha}"]
        findings = _gitleaks_git(root, ["--log-opts=" + " ".join(rev_args)])
        if findings is None:
            findings, engine = _builtin_range_scan(root, rev_args), "UDS built-in patterns; install Gitleaks for full coverage"
        all_findings.extend(findings)
    if all_findings:
        return 1, _report(all_findings, "outgoing commits", engine)
    return 0, f"UDS: no secrets detected in outgoing commits ({engine})."
