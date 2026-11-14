"""Project test detection and execution (used by `uds test` and after fixes)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

from universal_dev_security.config import ProjectConfig
from universal_dev_security.redaction import redact

NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1'
OUTPUT_TAIL = 6000


def _project_python(root: Path) -> str:
    for candidate in (root / ".venv" / "Scripts" / "python.exe", root / ".venv" / "bin" / "python",
                      root / "venv" / "Scripts" / "python.exe", root / "venv" / "bin" / "python"):
        if candidate.is_file():
            return str(candidate)
    return sys.executable


def _uses_pytest(root: Path) -> bool:
    if (root / "pytest.ini").is_file() or (root / "conftest.py").is_file():
        return True
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            data = {}
        if "pytest" in data.get("tool", {}):
            return True
    tests = root / "tests"
    return tests.is_dir() and any(tests.glob("test_*.py"))


def detect_test_command(root: Path, config: ProjectConfig | None = None) -> tuple[list[str] | None, str]:
    """Return (command, explanation). Commands are argument lists; no shell is used."""
    root = root.expanduser().resolve()
    if config and config.test_command:
        return list(config.test_command), "configured in .uds/config.toml"
    if _uses_pytest(root):
        return [_project_python(root), "-m", "pytest", "-q"], "pytest project detected"
    package = root / "package.json"
    if package.is_file():
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts", {})
        except (OSError, ValueError, AttributeError):
            scripts = {}
        if isinstance(scripts, dict) and scripts.get("test") and scripts["test"].strip() != NPM_DEFAULT_TEST:
            return ["npm", "test", "--silent"], "package.json test script"
    if any(root.glob("*.sln")) or any(root.glob("*.csproj")):
        return ["dotnet", "test"], ".NET solution/project"
    if (root / "pom.xml").is_file():
        return ["mvn", "-q", "test"], "Maven project"
    if (root / "gradlew").is_file() or (root / "gradlew.bat").is_file():
        return [str(root / ("gradlew.bat" if os.name == "nt" else "gradlew")), "test"], "Gradle wrapper"
    if (root / "go.mod").is_file():
        return ["go", "test", "./..."], "Go module"
    if (root / "Cargo.toml").is_file():
        return ["cargo", "test"], "Cargo project"
    if (root / "vendor" / "bin" / "phpunit").is_file():
        return [str(root / "vendor" / "bin" / "phpunit")], "PHPUnit"
    return None, "No test suite detected. Configure [testing] command in .uds/config.toml."


def run_tests(root: Path, config: ProjectConfig | None = None, timeout: int | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    command, why = detect_test_command(root, config)
    if not command:
        return {"status": "not_configured", "passed": None, "command": None, "message": why}
    executable = command[0]
    resolved = executable if Path(executable).is_file() else shutil.which(executable)
    if not resolved:
        return {"status": "error", "passed": False, "command": command, "message": f"{executable!r} was not found on PATH."}
    started = time.monotonic()
    try:
        # The command is the project's own, fixed test runner (no user-supplied arguments are
        # interpolated), so running Windows .cmd shims such as npm.cmd is acceptable here.
        completed = subprocess.run(  # noqa: S603
            [resolved, *command[1:]], cwd=str(root), stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout or (config.test_timeout_seconds if config else 900),
            check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "passed": False, "command": command, "message": "Test run timed out."}
    except OSError as exc:
        return {"status": "error", "passed": False, "command": command, "message": f"Could not start tests: {type(exc).__name__}"}
    output = redact((completed.stdout or "") + (completed.stderr or ""))[-OUTPUT_TAIL:]
    passed = completed.returncode == 0
    return {"status": "passed" if passed else "failed", "passed": passed, "command": command, "reason": why,
            "exit_code": completed.returncode, "duration_seconds": round(time.monotonic() - started, 2),
            "output_tail": output}
