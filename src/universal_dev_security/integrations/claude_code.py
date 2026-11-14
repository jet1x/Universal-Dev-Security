"""Claude Code integration: PreToolUse hooks that enforce the UDS policy.

Installed configuration (merged into ``.claude/settings.json``)::

    {"hooks": {"PreToolUse": [{"matcher": "<tools>", "hooks": [{"type": "command",
        "command": "uds hook claude-code", "timeout": 30}]}]},
     "permissions": {"ask": ["Bash(git push:*)"]}}

Hook protocol (Claude Code): the tool call is received as JSON on stdin. To
require approval or deny, the hook prints
``{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
"ask"|"deny", "permissionDecisionReason": "..."}}`` and exits 0. When UDS has
no objection it prints nothing, so Claude Code's normal permission flow still
applies (UDS never auto-approves anything).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from universal_dev_security.config import load_config
from universal_dev_security.integrations import apply_changes
from universal_dev_security.policy import Action, ActionKind, Decision, PolicyEngine

SETTINGS_PATH = ".claude/settings.json"
LOCAL_SETTINGS_PATH = ".claude/settings.local.json"
HOOK_MARKER = "hook claude-code"
MATCHER = "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read"
ASK_RULES = ["Bash(git push:*)", "PowerShell(git push:*)"]
_SAFE_PATH_RE = re.compile(r"^[\w\s.:\\/()+-]+$")


# ---------------------------------------------------------------------------
# Hook runtime
# ---------------------------------------------------------------------------

def _action_from_hook(payload: dict[str, Any], project_root: str) -> Action | None:
    tool = str(payload.get("tool_name") or "")
    data = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if tool in ("Bash", "PowerShell"):
        return Action(ActionKind.SHELL, command=str(data.get("command") or ""), project_root=project_root)
    if tool == "Write":
        return Action(ActionKind.WRITE_FILE, path=str(data.get("file_path") or ""),
                      content=str(data.get("content") or ""), project_root=project_root)
    if tool == "Edit":
        return Action(ActionKind.EDIT_FILE, path=str(data.get("file_path") or ""),
                      content=str(data.get("new_string") or ""), project_root=project_root)
    if tool == "MultiEdit":
        edits = data.get("edits") if isinstance(data.get("edits"), list) else []
        content = "\n".join(str(e.get("new_string") or "") for e in edits if isinstance(e, dict))
        return Action(ActionKind.EDIT_FILE, path=str(data.get("file_path") or ""), content=content,
                      project_root=project_root)
    if tool == "NotebookEdit":
        return Action(ActionKind.EDIT_FILE, path=str(data.get("notebook_path") or ""),
                      content=str(data.get("new_source") or ""), project_root=project_root)
    if tool == "Read":
        return Action(ActionKind.READ_FILE, path=str(data.get("file_path") or ""), project_root=project_root)
    return None


def _decision_output(decision: str, reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": f"UDS: {reason}"[:2000]}}


def handle_hook(payload: Any) -> dict[str, Any] | None:
    """Evaluate a Claude Code PreToolUse payload. Returns hook output or None (no objection)."""
    if not isinstance(payload, dict):
        return _decision_output("ask", "Unrecognized hook input; approval required.")
    if payload.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    project_root = os.environ.get("CLAUDE_PROJECT_DIR") or str(payload.get("cwd") or os.getcwd())
    action = _action_from_hook(payload, project_root)
    if action is None:
        return None
    try:
        config = load_config(Path(project_root))
    except ValueError:
        return _decision_output("ask", "The UDS project configuration could not be parsed; approval required.")
    decision = PolicyEngine(config).evaluate(action)
    if decision.decision is Decision.ALLOW:
        return None
    return _decision_output(decision.decision.value, decision.reason)


def run_hook(stdin_text: str) -> tuple[int, str]:
    """Entry point used by `uds hook claude-code`. Fails closed (ask) on any error."""
    try:
        payload = json.loads(stdin_text or "{}")
        output = handle_hook(payload)
    except Exception:  # noqa: BLE001 - a crashing guard must never silently allow
        output = _decision_output("ask", "Internal UDS hook error; approval required.")
    return 0, json.dumps(output) if output else ""


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

def hook_command(use_python_path: bool) -> str:
    if use_python_path:
        python = sys.executable
        if not _SAFE_PATH_RE.match(python):
            raise ValueError("The Python interpreter path contains characters that cannot be embedded safely.")
        return f'"{python}" -m universal_dev_security {HOOK_MARKER}'
    return f"uds {HOOK_MARKER}"


def _is_uds_hook(entry: Any) -> bool:
    return isinstance(entry, dict) and any(
        isinstance(h, dict) and HOOK_MARKER in str(h.get("command", "")) for h in entry.get("hooks", []) or [])


def merge_settings(existing: dict[str, Any], command: str) -> dict[str, Any]:
    settings = json.loads(json.dumps(existing))  # deep copy
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("Existing 'hooks' setting is not an object; refusing to modify it.")
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise ValueError("Existing 'hooks.PreToolUse' is not a list; refusing to modify it.")
    pre[:] = [entry for entry in pre if not _is_uds_hook(entry)]
    pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": command, "timeout": 30}]})
    permissions = settings.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise ValueError("Existing 'permissions' setting is not an object; refusing to modify it.")
    ask = permissions.setdefault("ask", [])
    if not isinstance(ask, list):
        raise ValueError("Existing 'permissions.ask' is not a list; refusing to modify it.")
    for rule in ASK_RULES:
        if rule not in ask:
            ask.append(rule)
    return settings


def remove_from_settings(existing: dict[str, Any]) -> dict[str, Any]:
    settings = json.loads(json.dumps(existing))
    hooks = settings.get("hooks")
    if isinstance(hooks, dict) and isinstance(hooks.get("PreToolUse"), list):
        hooks["PreToolUse"] = [e for e in hooks["PreToolUse"] if not _is_uds_hook(e)]
        if not hooks["PreToolUse"]:
            del hooks["PreToolUse"]
        if not hooks:
            del settings["hooks"]
    permissions = settings.get("permissions")
    if isinstance(permissions, dict) and isinstance(permissions.get("ask"), list):
        permissions["ask"] = [r for r in permissions["ask"] if r not in ASK_RULES]
        if not permissions["ask"]:
            del permissions["ask"]
        if not permissions:
            del settings["permissions"]
    return settings


def install(root: Path, *, apply: bool = False, remove: bool = False, local: bool = False,
            use_python_path: bool = False) -> dict[str, Any]:
    root = root.expanduser().resolve()
    relative = LOCAL_SETTINGS_PATH if local else SETTINGS_PATH
    path = root / relative
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8") or "{}")
        except ValueError as exc:
            raise ValueError(f"{relative} is not valid JSON; refusing to modify it. Fix it manually first.") from exc
        if not isinstance(existing, dict):
            raise ValueError(f"{relative} is not a JSON object; refusing to modify it.")
    if remove:
        updated = remove_from_settings(existing)
        new_content: str | None = json.dumps(updated, indent=2) + "\n" if (updated or path.is_file()) else None
    else:
        updated = merge_settings(existing, hook_command(use_python_path))
        new_content = json.dumps(updated, indent=2) + "\n"
    result = apply_changes(root, {relative: new_content}, f"claude-code integration ({'remove' if remove else 'install'})", apply)
    result["settings_file"] = relative
    if not remove:
        location = (f"The hook runs this Python interpreter directly ({sys.executable}); keep that environment "
                    "installed, and prefer --local because the path is machine-specific."
                    if use_python_path else
                    "The hook runs `uds` from PATH; if it is not on PATH the hook cannot run. Use --python-path to "
                    "embed this interpreter (recommended together with --local, because absolute paths are "
                    "machine-specific).")
        result["notes"] = [
            location,
            "The hook only adds 'ask'/'deny' decisions; it never auto-approves tool calls.",
            "`git push` additionally requires approval through permissions.ask as defense in depth.",
        ]
    return result
