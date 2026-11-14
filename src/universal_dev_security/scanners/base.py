"""Common scanner adapter contract and safe process execution."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from universal_dev_security.findings import Category, Finding, ScanResult, ScanStatus
from universal_dev_security.projectfiles import DEFAULT_EXCLUDED_DIRS, ProjectInventory

# Batch wrappers are executed through cmd.exe on Windows, where argument
# quoting cannot be made fully safe (see CVE-2024-24576 class of issues).
UNSAFE_WINDOWS_SUFFIXES = (".bat", ".cmd")
VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
MAX_OUTPUT_BYTES = 200 * 1024 * 1024


class ScannerExecutionError(RuntimeError):
    """Raised for scanner failures. Messages never contain raw scanner output."""


@dataclass
class ScanOptions:
    timeout_seconds: int = 600
    allow_network: bool = False
    semgrep_configs: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    @property
    def excluded_dirs(self) -> list[str]:
        return sorted(set(DEFAULT_EXCLUDED_DIRS) | {p.strip("/\\") for p in self.exclude_paths if p.strip("/\\")})


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    if not text:
        return None
    match = VERSION_RE.search(text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def format_version(version: tuple[int, int, int] | None) -> str | None:
    return ".".join(map(str, version)) if version else None


def _is_safe_executable(path: str) -> bool:
    if os.name == "nt" and path.lower().endswith(UNSAFE_WINDOWS_SUFFIXES):
        return False
    return Path(path).is_file()


def run_tool(
    args: list[str],
    *,
    cwd: Path,
    timeout: int,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a scanner safely: argument list, no shell, no stdin, bounded time.

    Callers must never print or persist ``stdout``/``stderr`` verbatim because
    scanners may echo secret material.
    """
    if not args or not all(isinstance(arg, str) for arg in args):
        raise ScannerExecutionError("Invalid scanner command")
    if any("\x00" in arg for arg in args):
        raise ScannerExecutionError("Scanner arguments may not contain NUL bytes")
    if not _is_safe_executable(args[0]):
        raise ScannerExecutionError("Refusing to execute a missing or batch-file scanner executable")
    env = dict(os.environ)
    env.update(env_overrides or {})
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.run(  # noqa: S603 - argument list, shell=False, validated executable
        args,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
        env=env,
        creationflags=creationflags,
    )


def _candidate_dirs(tool: str) -> list[Path]:
    """Well-known per-user install locations, checked after PATH."""
    home = Path.home()
    dirs = [Path(sys.executable).parent]  # same virtual environment as UDS (pip-installed semgrep)
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            winget = Path(local) / "Microsoft" / "WinGet"
            dirs.append(winget / "Links")
            patterns = {
                "gitleaks": "Gitleaks.Gitleaks_*",
                "trivy": "AquaSecurity.Trivy_*",
                "osv-scanner": "Google.OSVScanner_*",
            }
            if tool in patterns and (winget / "Packages").is_dir():
                dirs.extend(sorted((winget / "Packages").glob(patterns[tool])))
        dirs.append(home / "scoop" / "shims")
    else:
        dirs.extend([Path("/opt/homebrew/bin"), Path("/usr/local/bin"), home / ".local" / "bin"])
    dirs.append(home / "go" / "bin")
    return dirs


def find_executable(tool: str, names: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return (path, note). ``note`` explains refused candidates."""
    override = os.environ.get(f"UDS_{tool.upper().replace('-', '_')}_PATH")
    if override:
        if _is_safe_executable(override):
            return str(Path(override).resolve()), None
        return None, f"UDS_{tool.upper().replace('-', '_')}_PATH does not point to a usable executable."
    refused = None
    for name in names:
        found = shutil.which(name)
        if found:
            if _is_safe_executable(found):
                return found, None
            refused = found
    suffixes = (".exe",) if os.name == "nt" else ("",)
    for directory in _candidate_dirs(tool):
        for name in names:
            for suffix in suffixes:
                candidate = directory / f"{name}{suffix}"
                if candidate.is_file() and _is_safe_executable(str(candidate)):
                    return str(candidate), None
    if refused:
        return None, "Only a batch-file wrapper was found; UDS refuses to run .bat/.cmd scanners. Install the native executable."
    return None, None


def relative_path(value: Any, root: Path) -> str:
    """Normalize a scanner-reported path to a project-relative posix path."""
    text = str(value or "").strip()
    if not text:
        return ""
    candidate = Path(text)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            return candidate.name  # never leak paths outside the project
    normalized = text.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


class ScannerAdapter(ABC):
    name: str = ""
    display_name: str = ""
    category: Category = Category.CODE
    executable_names: tuple[str, ...] = ()
    min_version: tuple[int, int, int] = (0, 0, 0)
    version_args: tuple[str, ...] = ("--version",)
    # Privacy properties surfaced in reports and used by the scan policy.
    transmits_project_metadata: bool = False
    downloads_data: bool = False
    network_note: str = ""
    docs_url: str = ""
    install_hints: dict[str, str] = {}

    # -- discovery ------------------------------------------------------

    def locate(self) -> tuple[str | None, str | None]:
        return find_executable(self.name, self.executable_names)

    def detect_version(self, executable: str, cwd: Path) -> str | None:
        try:
            completed = run_tool([executable, *self.version_args], cwd=cwd, timeout=60)
        except (OSError, subprocess.SubprocessError, ScannerExecutionError):
            return None
        return format_version(parse_version(completed.stdout) or parse_version(completed.stderr))

    def is_compatible(self, version: str | None) -> bool:
        parsed = parse_version(version)
        return parsed is not None and parsed >= self.min_version

    def info(self, cwd: Path | None = None) -> dict[str, Any]:
        executable, note = self.locate()
        version = self.detect_version(executable, cwd or Path.cwd()) if executable else None
        return {
            "name": self.name,
            "display_name": self.display_name,
            "installed": executable is not None,
            "executable": executable,
            "version": version,
            "minimum_version": format_version(self.min_version),
            "compatible": self.is_compatible(version) if executable else None,
            "note": note,
            "transmits_project_metadata": self.transmits_project_metadata,
            "downloads_data": self.downloads_data,
            "network_note": self.network_note,
            "docs_url": self.docs_url,
            "install_hints": self.install_hints,
        }

    # -- execution ------------------------------------------------------

    @abstractmethod
    def applicable(self, inventory: ProjectInventory) -> tuple[bool, str]:
        """Return (applicable, reason)."""

    @abstractmethod
    def execute(self, executable: str, version: str, target: Path, options: ScanOptions) -> list[Finding]:
        """Run the scanner and return normalized findings, or raise ScannerExecutionError."""

    def scan(self, target: Path, inventory: ProjectInventory, options: ScanOptions) -> ScanResult:
        started = time.monotonic()
        root = target.expanduser().resolve()

        def result(status: ScanStatus, message: str, reason: str | None = None, version: str | None = None,
                   findings: list[Finding] | None = None) -> ScanResult:
            return ScanResult(
                tool=self.name, status=status, findings=findings or [], version=version, message=message,
                reason=reason, duration_seconds=round(time.monotonic() - started, 3),
            )

        applicable, why = self.applicable(inventory)
        if not applicable:
            return result(ScanStatus.NOT_APPLICABLE, why, "not_applicable")
        executable, note = self.locate()
        if not executable:
            hint = note or f"{self.display_name} was not found. See {self.docs_url} for official installation."
            return result(ScanStatus.NOT_INSTALLED, hint, "executable_not_found")
        version = self.detect_version(executable, root)
        if not self.is_compatible(version):
            return result(
                ScanStatus.SKIPPED,
                f"{self.display_name} version {version or 'unknown'} is not supported; "
                f"{format_version(self.min_version)} or newer is required.",
                "unsupported_version", version,
            )
        if self.transmits_project_metadata and not options.allow_network:
            return result(
                ScanStatus.SKIPPED,
                f"{self.display_name} was not run because it {self.network_note} "
                "Enable it with `uds scan --allow-network` or `[scanners] allow_network = true`.",
                "network_not_approved", version,
            )
        try:
            findings = self.execute(executable, version or "", root, options)
        except subprocess.TimeoutExpired:
            return result(ScanStatus.ERROR, f"{self.display_name} timed out after {options.timeout_seconds}s.",
                          "timeout", version)
        except ScannerExecutionError as exc:
            return result(ScanStatus.ERROR, str(exc), "execution_failed", version)
        except OSError as exc:
            return result(ScanStatus.ERROR, f"{self.display_name} could not be started ({type(exc).__name__}).",
                          "execution_failed", version)
        if findings:
            return result(ScanStatus.FINDINGS, f"{len(findings)} finding(s) reported by {self.display_name}.",
                          version=version, findings=findings)
        return result(ScanStatus.CLEAN, f"No findings reported by {self.display_name}.", version=version)
