"""Recovery points and rollback for UDS-made changes.

Every UDS modification (fixes, integration installs) follows:

    checkpoint = rm.create(label, paths)   # snapshot "before"
    ... modify files (safe_write) ...
    rm.seal(checkpoint)                    # record "after" hashes

Rollback restores the "before" state only for files whose current content still
matches the recorded "after" hash, so later user edits are never clobbered
unless ``force`` is given.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHECKPOINT_ID_RE = re.compile(r"^\d{8}T\d{6}(?:\d{6})?Z-[0-9a-f]{6}$")


class RecoveryError(ValueError):
    pass


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_inside(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root``; reject traversal and symlink escapes."""
    if not relative or "\x00" in relative:
        raise RecoveryError("Empty or invalid path")
    # Treat backslashes as separators and reject drive prefixes on every OS, so the
    # same input is accepted or rejected identically on Windows, Linux and macOS.
    normalized = relative.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise RecoveryError(f"Absolute paths are not allowed: {relative}")
    candidate = Path(normalized)
    if candidate.is_absolute() or candidate.drive or ".." in candidate.parts:
        raise RecoveryError(f"Path traversal is not allowed: {relative}")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise RecoveryError(f"Path escapes the project directory: {relative}") from exc
    return resolved


def safe_write(root: Path, relative: str, content: str) -> Path:
    """Atomically write a text file inside ``root`` (temp file + replace)."""
    target = resolve_inside(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".uds-tmp-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        if target.exists():
            shutil.copymode(target, temp)
        os.replace(temp, target)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    return target


class RecoveryManager:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.base = self.root / ".uds" / "backups"

    def _dir(self, checkpoint_id: str) -> Path:
        if not CHECKPOINT_ID_RE.match(checkpoint_id):
            raise RecoveryError(f"Invalid checkpoint id: {checkpoint_id!r}")
        return self.base / checkpoint_id

    def create(self, label: str, paths: list[str]) -> str:
        from universal_dev_security.history import ensure_uds_dir

        ensure_uds_dir(self.root)
        checkpoint_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:6]
        directory = self._dir(checkpoint_id)
        files_dir = directory / "files"
        files_dir.mkdir(parents=True)
        entries = []
        for relative in dict.fromkeys(paths):
            source = resolve_inside(self.root, relative)
            if source.is_symlink():
                raise RecoveryError(f"Refusing to manage a symbolic link: {relative}")
            existed = source.is_file()
            if existed:
                backup = files_dir / Path(relative)
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, backup)
            entries.append({"path": Path(relative).as_posix(), "existed": existed,
                            "sha256_before": sha256_file(source), "sha256_after": None})
        manifest = {"id": checkpoint_id, "label": label[:200], "created_at": datetime.now(timezone.utc).isoformat(),
                    "sealed": False, "restored": False, "entries": entries}
        self._save(checkpoint_id, manifest)
        return checkpoint_id

    def seal(self, checkpoint_id: str) -> dict[str, Any]:
        manifest = self.load(checkpoint_id)
        for entry in manifest["entries"]:
            entry["sha256_after"] = sha256_file(resolve_inside(self.root, entry["path"]))
        manifest["sealed"] = True
        self._save(checkpoint_id, manifest)
        return manifest

    def _save(self, checkpoint_id: str, manifest: dict[str, Any]) -> None:
        path = self._dir(checkpoint_id) / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

    def load(self, checkpoint_id: str) -> dict[str, Any]:
        path = self._dir(checkpoint_id) / "manifest.json"
        if not path.is_file():
            raise RecoveryError(f"Checkpoint not found: {checkpoint_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self) -> list[dict[str, Any]]:
        if not self.base.is_dir():
            return []
        result = []
        for directory in sorted(self.base.iterdir()):
            if CHECKPOINT_ID_RE.match(directory.name) and (directory / "manifest.json").is_file():
                manifest = self.load(directory.name)
                result.append({"id": manifest["id"], "label": manifest["label"], "created_at": manifest["created_at"],
                               "files": [e["path"] for e in manifest["entries"]], "restored": manifest.get("restored", False)})
        return result

    def restore(self, checkpoint_id: str, *, force: bool = False) -> dict[str, Any]:
        manifest = self.load(checkpoint_id)
        restored, conflicts, unchanged = [], [], []
        for entry in manifest["entries"]:
            target = resolve_inside(self.root, entry["path"])
            current = sha256_file(target)
            if current == entry["sha256_before"]:
                unchanged.append(entry["path"])
                continue
            expected_after = entry.get("sha256_after")
            if not force and manifest.get("sealed") and current != expected_after:
                conflicts.append(entry["path"])  # modified after UDS changed it: keep the user's work
                continue
            if entry["existed"]:
                backup = self._dir(checkpoint_id) / "files" / Path(entry["path"])
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, target)
            elif target.is_file():
                target.unlink()
            restored.append(entry["path"])
        if not conflicts:
            manifest["restored"] = True
            self._save(checkpoint_id, manifest)
        return {"checkpoint": checkpoint_id, "restored": restored, "conflicts": conflicts, "unchanged": unchanged,
                "status": "conflicts" if conflicts else "restored"}
