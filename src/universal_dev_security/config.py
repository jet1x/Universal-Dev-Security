"""Load and validate project configuration (``.uds/config.toml``).

Project configuration can only *add* restrictions. Settings that would weaken
the mandatory global policy are ignored and reported as warnings.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_RELATIVE_PATH = Path(".uds") / "config.toml"

KNOWN_SCANNERS = ("gitleaks", "semgrep", "osv-scanner", "trivy")
FAIL_ON_LEVELS = ("none", "unclassified", "low", "medium", "high", "critical")
SECURITY_MODES = ("balanced", "strict")

# Mandatory settings: the only accepted value is the safe one.
MANDATORY_TRUE = (
    "require_user_approval_for_high_risk_changes",
    "require_user_approval_for_git_push",
)


class ConfigError(ValueError):
    """Raised when the configuration file cannot be parsed."""


@dataclass
class ProjectConfig:
    path: Path | None = None
    exists: bool = False
    project_name: str = ""
    profile: str = "auto"
    security_mode: str = "balanced"
    allow_automatic_low_risk_fixes: bool = True
    require_user_approval_for_high_risk_changes: bool = True
    require_user_approval_for_git_push: bool = True
    fail_on: str = "none"
    deny_command_patterns: list[str] = field(default_factory=list)
    approval_command_patterns: list[str] = field(default_factory=list)
    protected_paths: list[str] = field(default_factory=list)
    enabled_scanners: list[str] = field(default_factory=lambda: list(KNOWN_SCANNERS))
    allow_network: bool = False
    semgrep_configs: list[str] = field(default_factory=list)
    scanner_timeout_seconds: int = 600
    exclude_paths: list[str] = field(default_factory=list)
    test_command: list[str] = field(default_factory=list)
    test_timeout_seconds: int = 900
    history_limit: int = 50
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "exists": self.exists,
            "project": {"name": self.project_name, "profile": self.profile},
            "policy": {
                "security_mode": self.security_mode,
                "allow_automatic_low_risk_fixes": self.allow_automatic_low_risk_fixes,
                "require_user_approval_for_high_risk_changes": self.require_user_approval_for_high_risk_changes,
                "require_user_approval_for_git_push": self.require_user_approval_for_git_push,
                "fail_on": self.fail_on,
                "deny_command_patterns": self.deny_command_patterns,
                "approval_command_patterns": self.approval_command_patterns,
                "protected_paths": self.protected_paths,
            },
            "scanners": {
                "enabled": self.enabled_scanners,
                "allow_network": self.allow_network,
                "semgrep_configs": self.semgrep_configs,
                "timeout_seconds": self.scanner_timeout_seconds,
                "exclude_paths": self.exclude_paths,
            },
            "testing": {"command": self.test_command, "timeout_seconds": self.test_timeout_seconds},
            "history": {"limit": self.history_limit},
            "warnings": self.warnings,
        }


def _str_list(value: Any, key: str, warnings: list[str], max_items: int = 200) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        warnings.append(f"{key} must be a list of strings; ignored.")
        return []
    return [item for item in value if item.strip()][:max_items]


def _bounded_int(value: Any, key: str, default: int, low: int, high: int, warnings: list[str]) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        warnings.append(f"{key} must be an integer between {low} and {high}; using {default}.")
        return default
    return value


def load_config(project_root: Path) -> ProjectConfig:
    root = project_root.expanduser().resolve()
    path = root / CONFIG_RELATIVE_PATH
    config = ProjectConfig(path=path)
    if not path.is_file():
        return config
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Could not parse {path}: {type(exc).__name__}") from exc
    config.exists = True
    warnings = config.warnings

    project = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
    config.project_name = str(project.get("name", ""))[:200]
    config.profile = str(project.get("profile", "auto"))[:50]

    policy = data.get("policy", {}) if isinstance(data.get("policy"), dict) else {}
    mode = policy.get("security_mode", "balanced")
    if mode in SECURITY_MODES:
        config.security_mode = mode
    else:
        warnings.append(f"Unknown security_mode {mode!r}; using 'balanced'.")
    if isinstance(policy.get("allow_automatic_low_risk_fixes"), bool):
        config.allow_automatic_low_risk_fixes = policy["allow_automatic_low_risk_fixes"]
    for key in MANDATORY_TRUE:
        if key in policy and policy[key] is not True:
            warnings.append(
                f"policy.{key} cannot be disabled: the mandatory global policy requires it. Setting ignored."
            )
    fail_on = policy.get("fail_on", "none")
    if fail_on in FAIL_ON_LEVELS:
        config.fail_on = fail_on
    else:
        warnings.append(f"Unknown policy.fail_on {fail_on!r}; using 'none'.")
    config.deny_command_patterns = _str_list(policy.get("deny_command_patterns"), "policy.deny_command_patterns", warnings)
    config.approval_command_patterns = _str_list(
        policy.get("approval_command_patterns"), "policy.approval_command_patterns", warnings
    )
    config.protected_paths = _str_list(policy.get("protected_paths"), "policy.protected_paths", warnings)
    for key in ("allow_commands", "allowed_commands", "disable_rules", "disabled_rules"):
        if key in policy:
            warnings.append(f"policy.{key} is not supported: global rules cannot be disabled by project configuration.")

    scanners = data.get("scanners", {}) if isinstance(data.get("scanners"), dict) else {}
    if "enabled" in scanners:
        enabled = _str_list(scanners.get("enabled"), "scanners.enabled", warnings)
        unknown = [name for name in enabled if name not in KNOWN_SCANNERS]
        if unknown:
            warnings.append(f"Unknown scanners ignored: {', '.join(unknown)}")
        config.enabled_scanners = [name for name in enabled if name in KNOWN_SCANNERS]
        if "gitleaks" not in config.enabled_scanners:
            # Secret scanning is a mandatory global control.
            config.enabled_scanners.insert(0, "gitleaks")
            warnings.append("gitleaks secret scanning is mandatory and was re-enabled.")
    if isinstance(scanners.get("allow_network"), bool):
        config.allow_network = scanners["allow_network"]
    config.semgrep_configs = _str_list(scanners.get("semgrep_configs"), "scanners.semgrep_configs", warnings, 20)
    config.scanner_timeout_seconds = _bounded_int(
        scanners.get("timeout_seconds"), "scanners.timeout_seconds", 600, 10, 7200, warnings
    )
    config.exclude_paths = _str_list(scanners.get("exclude_paths"), "scanners.exclude_paths", warnings)

    testing = data.get("testing", {}) if isinstance(data.get("testing"), dict) else {}
    config.test_command = _str_list(testing.get("command"), "testing.command", warnings, 50)
    config.test_timeout_seconds = _bounded_int(
        testing.get("timeout_seconds"), "testing.timeout_seconds", 900, 10, 7200, warnings
    )

    history = data.get("history", {}) if isinstance(data.get("history"), dict) else {}
    config.history_limit = _bounded_int(history.get("limit"), "history.limit", 50, 1, 1000, warnings)
    return config
