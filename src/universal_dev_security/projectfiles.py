"""Bounded, symlink-safe project file inventory used by detection and scanners."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are never project source and are expensive to walk.
DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".uds", ".venv", "venv", "env", ".tox", ".nox", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules", "bower_components",
    ".next", ".nuxt", ".svelte-kit", "dist", "build", "out", "target", "bin", "obj",
    ".gradle", ".idea", ".vs", ".vscode", "coverage", "htmlcov", ".terraform", ".cache",
    "site-packages", ".eggs",
})


@dataclass
class ProjectInventory:
    root: Path
    files: list[str] = field(default_factory=list)   # posix paths relative to root
    truncated: bool = False

    @property
    def names(self) -> set[str]:
        return {path.rsplit("/", 1)[-1] for path in self.files}

    @property
    def suffixes(self) -> set[str]:
        result = set()
        for path in self.files:
            name = path.rsplit("/", 1)[-1]
            if "." in name:
                result.add("." + name.rsplit(".", 1)[-1].lower())
        return result

    def has_name(self, *names: str) -> bool:
        wanted = {n.lower() for n in names}
        return any(name.lower() in wanted for name in self.names)

    def has_suffix(self, *suffixes: str) -> bool:
        return bool(self.suffixes & {s.lower() for s in suffixes})

    def find(self, name: str) -> list[str]:
        lowered = name.lower()
        return [p for p in self.files if p.rsplit("/", 1)[-1].lower() == lowered]

    def has_path_part(self, part: str) -> bool:
        needle = part.strip("/").lower()
        return any(f"/{needle}/" in f"/{p.lower()}" for p in self.files)


def build_inventory(
    root: Path,
    *,
    max_files: int = 50_000,
    max_depth: int = 12,
    extra_excludes: list[str] | None = None,
) -> ProjectInventory:
    """Walk ``root`` without following symlinks, skipping heavy directories."""
    resolved = root.expanduser().resolve()
    inventory = ProjectInventory(root=resolved)
    excluded = set(DEFAULT_EXCLUDED_DIRS) | {e.strip("/\\") for e in (extra_excludes or []) if e}
    base_depth = len(resolved.parts)
    for current, dirs, files in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.parts) - base_depth
        dirs[:] = sorted(
            d for d in dirs
            if d not in excluded and not (current_path / d).is_symlink() and depth < max_depth
        )
        for name in sorted(files):
            relative = (current_path / name).relative_to(resolved).as_posix()
            if relative in excluded:
                continue
            inventory.files.append(relative)
            if len(inventory.files) >= max_files:
                inventory.truncated = True
                return inventory
    return inventory
