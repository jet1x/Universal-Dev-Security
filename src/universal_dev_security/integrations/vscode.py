"""VS Code integration: tasks for scanning and opening the dashboard."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from universal_dev_security.integrations import apply_changes

TASKS_PATH = ".vscode/tasks.json"
LABEL_PREFIX = "UDS: "

UDS_TASKS = [
    {"label": "UDS: Security scan", "type": "process", "command": "uds", "args": ["scan", "${workspaceFolder}"],
     "group": "test", "problemMatcher": []},
    {"label": "UDS: Open dashboard", "type": "process", "command": "uds",
     "args": ["dashboard", "${workspaceFolder}", "--open"], "problemMatcher": []},
    {"label": "UDS: Doctor", "type": "process", "command": "uds", "args": ["doctor", "${workspaceFolder}"],
     "problemMatcher": []},
]


def install(root: Path, *, apply: bool = False, remove: bool = False) -> dict[str, Any]:
    root = root.expanduser().resolve()
    path = root / TASKS_PATH
    data: dict[str, Any] = {"version": "2.0.0", "tasks": []}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            # tasks.json may contain comments (JSONC); never rewrite what we cannot parse faithfully.
            raise ValueError(f"{TASKS_PATH} is not plain JSON (it may contain comments); refusing to modify it. "
                             "Add the UDS tasks manually (see docs/integrations.md).") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tasks", []), list):
            raise ValueError(f"{TASKS_PATH} has an unexpected structure; refusing to modify it.")
    tasks = [t for t in data.get("tasks", []) if not (isinstance(t, dict) and str(t.get("label", "")).startswith(LABEL_PREFIX))]
    if not remove:
        tasks.extend(UDS_TASKS)
    data["tasks"] = tasks
    data.setdefault("version", "2.0.0")
    content = json.dumps(data, indent=2) + "\n"
    result = apply_changes(root, {TASKS_PATH: content}, "vscode tasks " + ("remove" if remove else "install"), apply)
    result["tasks_file"] = TASKS_PATH
    return result
