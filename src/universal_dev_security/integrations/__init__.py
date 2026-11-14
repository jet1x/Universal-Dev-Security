"""Integrations with AI coding tools, Git hosting and editors.

All integrations follow the same safety contract:
* dry-run by default — show the planned change and a diff;
* ``apply=True`` creates a recovery checkpoint first, then writes atomically;
* existing user configuration is merged, never silently overwritten;
* removal only deletes UDS-owned entries.
"""
from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from universal_dev_security.recovery import RecoveryManager, resolve_inside, safe_write


def apply_changes(root: Path, changes: dict[str, str | None], label: str, apply: bool) -> dict[str, Any]:
    """Plan (and optionally apply) file changes. ``None`` content deletes a file."""
    root = root.expanduser().resolve()
    planned = []
    for relative, new in changes.items():
        path = resolve_inside(root, relative)
        old = path.read_text(encoding="utf-8") if path.is_file() else None
        if old == new:
            continue
        diff = "".join(difflib.unified_diff(
            (old or "").splitlines(keepends=True), (new or "").splitlines(keepends=True),
            fromfile=f"a/{relative}", tofile=f"b/{relative}"))
        planned.append({"path": relative, "action": "delete" if new is None else ("update" if old is not None else "create"),
                        "diff": diff})
    result: dict[str, Any] = {"applied": False, "changes": planned, "checkpoint": None}
    if not apply or not planned:
        result["applied"] = apply and not planned
        return result
    manager = RecoveryManager(root)
    checkpoint = manager.create(label, [c["path"] for c in planned])
    for change in planned:
        content = changes[change["path"]]
        if content is None:
            resolve_inside(root, change["path"]).unlink(missing_ok=True)
        else:
            safe_write(root, change["path"], content)
    manager.seal(checkpoint)
    result.update(applied=True, checkpoint=checkpoint)
    return result
