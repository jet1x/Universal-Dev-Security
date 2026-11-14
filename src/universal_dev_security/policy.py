"""Central UDS security policy engine.

Every integration (CLI, Git hooks, Claude Code hooks, generic AI agents)
describes what it is about to do as an :class:`Action`. The engine evaluates it
against the immutable global rules plus any *additional* restrictions from the
project configuration and returns a :class:`PolicyDecision`.

Precedence: mandatory global policy > technology profile > project config.
Project configuration can add deny/approval rules and protected paths, but it
cannot remove or downgrade a global rule.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from universal_dev_security.config import ProjectConfig
from universal_dev_security.redaction import find_secrets


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"      # explicit user approval required
    DENY = "deny"

    @property
    def rank(self) -> int:
        return {"allow": 0, "ask": 1, "deny": 2}[self.value]


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class ActionKind(str, Enum):
    SHELL = "shell"
    WRITE_FILE = "write_file"
    EDIT_FILE = "edit_file"
    READ_FILE = "read_file"
    DELETE_FILE = "delete_file"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    PUBLISH = "publish"


@dataclass
class Action:
    kind: ActionKind
    command: str = ""
    path: str = ""
    content: str = ""
    actor: str = "ai"            # "ai", "user", "ci", "hook"
    project_root: str = ""

    def __post_init__(self) -> None:
        self.kind = ActionKind(self.kind)
        # Bound the amount of text inspected to keep evaluation fast.
        self.command = (self.command or "")[:100_000]
        self.content = (self.content or "")[:2_000_000]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        if not isinstance(data, dict):
            raise ValueError("Action must be a JSON object")
        kind = data.get("action") or data.get("kind")
        try:
            action_kind = ActionKind(kind)
        except ValueError as exc:
            raise ValueError(f"Unknown action kind: {kind!r}") from exc
        return cls(
            kind=action_kind,
            command=str(data.get("command", "") or ""),
            path=str(data.get("path", "") or ""),
            content=str(data.get("content", "") or ""),
            actor=str(data.get("actor", "ai") or "ai"),
            project_root=str(data.get("project_root", "") or ""),
        )


@dataclass
class RuleMatch:
    rule_id: str
    decision: Decision
    risk: Risk
    reason: str
    source: str = "global"   # "global" or "project"

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "decision": self.decision.value,
            "risk": self.risk.value,
            "reason": self.reason,
            "source": self.source,
        }


@dataclass
class PolicyDecision:
    decision: Decision
    risk: Risk
    matches: list[RuleMatch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        if not self.matches:
            return "No UDS policy rule matched."
        relevant = [m for m in self.matches if m.decision is self.decision] or self.matches
        return "; ".join(f"[{m.rule_id}] {m.reason}" for m in relevant)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk": self.risk.value,
            "reason": self.reason,
            "matches": [match.to_dict() for match in self.matches],
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------
# Shell command rules
# --------------------------------------------------------------------------

MAX_ANALYZED_COMMAND_CHARS = 20_000

_GIT = r"\bgit(?:\.exe)?(?:\s+(?:-C\s+\S+|-c\s+\S+|--[\w-]+(?:=\S+)?))*\s+"


@dataclass(frozen=True)
class CommandRule:
    rule_id: str
    pattern: re.Pattern[str]
    decision: Decision
    risk: Risk
    reason: str


def _rule(rule_id: str, pattern: str, decision: Decision, risk: Risk, reason: str) -> CommandRule:
    return CommandRule(rule_id, re.compile(pattern, re.IGNORECASE), decision, risk, reason)


GLOBAL_COMMAND_RULES: tuple[CommandRule, ...] = (
    _rule("git-hook-bypass", _GIT + r"(?:(?:commit|merge|am)\b.{0,1000}(?:--no-verify|\s-[a-z]*n[a-z]*\b(?!\s*=))|(?:push|rebase)\b.{0,1000}--no-verify)",
          Decision.DENY, Risk.CRITICAL, "Bypassing Git hooks disables UDS protections."),
    _rule("git-hooks-path-change", _GIT + r"config\b.{0,1000}\bcore\.hooksPath\b",
          Decision.ASK, Risk.HIGH, "Changing core.hooksPath can disable UDS Git protection."),
    _rule("git-force-push", _GIT + r"push\b.{0,1000}(?:--force\b|--force-with-lease\b|--force-if-includes\b|\s-f\b|\s\+\S+)",
          Decision.ASK, Risk.CRITICAL, "Force push rewrites remote history and requires explicit approval."),
    _rule("git-push", _GIT + r"push\b",
          Decision.ASK, Risk.HIGH, "Git push always requires explicit user approval."),
    _rule("git-commit", _GIT + r"commit\b",
          Decision.ASK, Risk.MEDIUM, "Commits require explicit user approval (staged content should be scanned)."),
    _rule("git-history-rewrite", _GIT + r"(?:filter-branch|filter-repo|replace)\b|" + _GIT + r"rebase\b|" + _GIT + r"reset\s+--hard\b",
          Decision.ASK, Risk.HIGH, "History rewrites and hard resets can destroy work."),
    _rule("git-discard-changes", _GIT + r"(?:clean\s+-[a-z]*f|checkout\s+(?:--\s+)?\.(?:\s|$)|restore\s+(?:--\S+\s+)*\.(?:\s|$)|stash\s+(?:drop|clear)\b|branch\s+-D\b)",
          Decision.ASK, Risk.HIGH, "This Git command discards uncommitted work or branches."),
    _rule("git-global-config", _GIT + r"config\s+(?:--global|--system)\b",
          Decision.ASK, Risk.HIGH, "Global Git configuration changes affect every project on this machine."),
    _rule("delete-root", r"\brm\s+(?:-[a-z]*\s+)*(?:/|~|\$HOME|/\*|[a-z]:\\?)\s*$|\bRemove-Item\b.{0,1000}\s(?:[a-z]:\\|~)\s*(?:-|$)|\bformat\s+[a-z]:|\bmkfs(?:\.\w+)?\b|\bdd\s+if=",
          Decision.DENY, Risk.CRITICAL, "Command could destroy a whole drive or home directory."),
    _rule("recursive-delete", r"\brm\s+(?:-[a-z]*r[a-z]*|-[a-z]*R[a-z]*|--recursive)\b|\bRemove-Item\b.{0,1000}-Recurse|\b(?:rd|rmdir)\s+/s\b|\bdel\s+(?:/[a-z]\s+)*/s\b|\bshutil\.rmtree\b",
          Decision.ASK, Risk.HIGH, "Recursive deletion requires explicit approval."),
    _rule("remote-code-execution", r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|]{0,1000}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python\d*|iex|Invoke-Expression|pwsh|powershell)\b|\biex\s*\(.{0,1000}DownloadString|Invoke-Expression\s*\(.{0,1000}(?:DownloadString|Invoke-WebRequest|irm|iwr)",
          Decision.ASK, Risk.CRITICAL, "Piping downloaded content into an interpreter executes unreviewed code."),
    _rule("system-security-settings", r"\bSet-MpPreference\b|\bAdd-MpPreference\b.{0,1000}-Exclusion|\bnetsh\s+(?:adv)?firewall\b.{0,1000}\b(?:off|disable)\b|\bSet-NetFirewallProfile\b.{0,1000}-Enabled\s+False|\bSet-ExecutionPolicy\b.{0,1000}\b(?:Unrestricted|Bypass)\b.{0,1000}-Scope\s+LocalMachine|\bbcdedit\b|\bsetenforce\s+0\b|\bufw\s+disable\b|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b",
          Decision.DENY, Risk.CRITICAL, "Changing machine security settings is outside the UDS authorization boundary."),
    _rule("system-wide-install", r"\b(?:npm|pnpm|yarn)\s+(?:install|i|add)\s+(?:.{0,1000}\s)?(?:-g|--global)\b|\b(?:winget|choco|scoop|brew|apt|apt-get|dnf|yum|pacman|zypper|snap)\s+install\b|\bsudo\b|\bpip3?\s+install\b.{0,1000}--user\b|\bmsiexec\b",
          Decision.ASK, Risk.HIGH, "System-wide or privileged installation requires approval."),
    _rule("publish", r"\b(?:npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b|\b(?:poetry|uv|flit|hatch)\s+publish\b|\bcargo\s+publish\b|\bgem\s+push\b|\bdotnet\s+nuget\s+push\b|\bdocker\s+push\b|\bgh\s+release\s+create\b|\bgh\s+repo\s+create\b|\bgh\s+pr\s+(?:create|merge)\b|\bmvn\b.{0,1000}\bdeploy\b|\bcomposer\s+publish\b",
          Decision.ASK, Risk.HIGH, "Publishing or uploading requires explicit approval."),
    _rule("secret-file-access", r"(?:^|[\s\"'=<>/\\])(?:\.env(?!\.(?:example|sample|template|dist)\b)(?:\.[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|[\w.-]+\.pem|[\w.-]+\.p12|[\w.-]+\.pfx|[\w.-]+\.key|credentials(?:\.json)?|\.npmrc|\.pypirc|\.netrc)(?=$|[\s\"'|;&>)])",
          Decision.ASK, Risk.MEDIUM, "Command touches a file that commonly contains credentials."),
    _rule("security-control-modification", r"(?:^|[\s\"'=/\\])(?:\.uds[/\\]|\.claude[/\\]settings(?:\.local)?\.json|\.git[/\\]hooks\b|\.gitleaks\.toml|\.gitleaksignore)",
          Decision.ASK, Risk.HIGH, "Command touches UDS, Claude Code, or Git hook security configuration."),
    _rule("uds-protection-removal", r"\buds(?:\.exe)?\s+(?:hooks\s+uninstall|integrate\s+\S+\s+--remove|rollback)\b",
          Decision.ASK, Risk.HIGH, "Removing UDS protections or rolling back requires explicit approval."),
    _rule("world-writable-permissions", r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+w|o\+w)\b|\bicacls\b.{0,1000}\bEveryone:\(?F",
          Decision.ASK, Risk.MEDIUM, "Granting world-writable permissions weakens file security."),
)

# --------------------------------------------------------------------------
# File rules
# --------------------------------------------------------------------------

SECRET_FILE_GLOBS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_rsa*", "id_ed25519*", "id_ecdsa*",
    ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json", "*.keystore", "*.jks",
)
SECRET_FILE_ALLOW = (".env.example", ".env.sample", ".env.template", ".env.dist")

SECURITY_CONTROL_GLOBS = (
    ".uds/*", ".uds/**", ".claude/settings.json", ".claude/settings.local.json", ".git/hooks/*",
    ".git/config", ".gitleaks.toml", ".gitleaksignore", ".semgrepignore", ".trivyignore",
)
CI_GLOBS = (".github/workflows/*", ".github/workflows/**", ".gitlab-ci.yml", "azure-pipelines.yml")


def _relative_posix(path: str, project_root: str) -> tuple[str, bool]:
    """Return (relative posix path, inside_project)."""
    if not path:
        return "", True
    candidate = Path(path)
    if project_root:
        root = Path(project_root).expanduser().resolve()
        absolute = candidate if candidate.is_absolute() else root / candidate
        try:
            resolved = absolute.resolve()
        except (OSError, RuntimeError):
            return path.replace("\\", "/"), False
        try:
            return resolved.relative_to(root).as_posix(), True
        except ValueError:
            return resolved.as_posix(), False
    normalized = path.replace("\\", "/")
    inside = not candidate.is_absolute() and ".." not in PurePosixPath(normalized).parts
    return normalized.lstrip("./") if normalized.startswith("./") else normalized, inside


def _matches_any(relative: str, globs: tuple[str, ...] | list[str]) -> bool:
    name = PurePosixPath(relative).name
    lowered = relative.lower()
    for glob in globs:
        glob_l = glob.lower()
        if fnmatch.fnmatchcase(lowered, glob_l) or fnmatch.fnmatchcase(name.lower(), glob_l):
            return True
        if glob_l.endswith("/**") and (lowered + "/").startswith(glob_l[:-2]):
            return True
    return False


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, config: ProjectConfig | None = None) -> None:
        self.config = config or ProjectConfig()
        self._project_command_rules: list[CommandRule] = []
        self.warnings: list[str] = list(self.config.warnings)
        for pattern in self.config.deny_command_patterns:
            self._add_project_rule("project-deny", pattern, Decision.DENY, Risk.HIGH)
        for pattern in self.config.approval_command_patterns:
            self._add_project_rule("project-approval", pattern, Decision.ASK, Risk.MEDIUM)

    def _add_project_rule(self, rule_id: str, pattern: str, decision: Decision, risk: Risk) -> None:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            self.warnings.append(f"Invalid project command pattern ignored: {pattern!r}")
            return
        self._project_command_rules.append(
            CommandRule(rule_id, compiled, decision, risk, f"Project policy matched pattern {pattern!r}.")
        )

    # -- public API -----------------------------------------------------

    def evaluate(self, action: Action) -> PolicyDecision:
        handlers: dict[ActionKind, Callable[[Action], list[RuleMatch]]] = {
            ActionKind.SHELL: self._evaluate_shell,
            ActionKind.WRITE_FILE: self._evaluate_write,
            ActionKind.EDIT_FILE: self._evaluate_write,
            ActionKind.READ_FILE: self._evaluate_read,
            ActionKind.DELETE_FILE: self._evaluate_delete,
            ActionKind.GIT_COMMIT: lambda a: [RuleMatch("git-commit", Decision.ASK, Risk.MEDIUM,
                                                        "Commits require explicit user approval.")],
            ActionKind.GIT_PUSH: lambda a: [RuleMatch("git-push", Decision.ASK, Risk.HIGH,
                                                      "Git push always requires explicit user approval.")],
            ActionKind.PUBLISH: lambda a: [RuleMatch("publish", Decision.ASK, Risk.HIGH,
                                                     "Publishing requires explicit approval.")],
        }
        matches = handlers[action.kind](action)
        return self._combine(matches)

    def _combine(self, matches: list[RuleMatch]) -> PolicyDecision:
        if not matches:
            return PolicyDecision(Decision.ALLOW, Risk.LOW, [], list(self.warnings))
        if self.config.security_mode == "strict":
            for match in matches:
                if match.risk is Risk.CRITICAL and match.decision is Decision.ASK:
                    match.decision = Decision.DENY
                    match.reason += " (strict mode: denied)"
        decision = max((m.decision for m in matches), key=lambda d: d.rank)
        risk = max((m.risk for m in matches), key=lambda r: r.rank)
        return PolicyDecision(decision, risk, matches, list(self.warnings))

    # -- shell ----------------------------------------------------------

    def _evaluate_shell(self, action: Action) -> list[RuleMatch]:
        command = action.command
        matches: list[RuleMatch] = []
        seen: set[str] = set()
        if len(command) > MAX_ANALYZED_COMMAND_CHARS:
            # Too long to analyze reliably and cheaply: never allow silently.
            return [RuleMatch("command-too-long", Decision.ASK, Risk.HIGH,
                              f"Command exceeds {MAX_ANALYZED_COMMAND_CHARS} characters and was not analyzed.")]
        parts = [s for s in re.split(r"\r?\n|;|&&|\|\||(?<!\|)&(?!&)", command) if s.strip()]
        segments = parts if len(parts) > 1 else [command]
        if len(parts) > 1 and "\n" in command:
            segments.append(command)  # keep cross-line context (e.g. heredocs piped to an interpreter)
        for segment in segments:
            normalized = " ".join(segment.split())
            rules = list(GLOBAL_COMMAND_RULES) + self._project_command_rules
            for rule in rules:
                if rule.rule_id in seen:
                    continue
                if rule.pattern.search(normalized):
                    # A force push also matches the generic push rule; keep the stronger one.
                    if rule.rule_id == "git-push" and "git-force-push" in seen:
                        continue
                    seen.add(rule.rule_id)
                    source = "project" if rule.rule_id.startswith("project-") else "global"
                    matches.append(RuleMatch(rule.rule_id, rule.decision, rule.risk, rule.reason, source))
        if find_secrets(command):
            matches.append(RuleMatch("secret-in-command", Decision.ASK, Risk.HIGH,
                                     "Command contains a likely credential; it would be stored in shell history and logs."))
        for protected in self.config.protected_paths:
            if protected and protected.replace("\\", "/").lower() in command.replace("\\", "/").lower():
                matches.append(RuleMatch("project-protected-path", Decision.ASK, Risk.HIGH,
                                         f"Command references protected path {protected!r}.", "project"))
                break
        return matches

    # -- files ----------------------------------------------------------

    def _path_matches(self, action: Action, *, write: bool) -> list[RuleMatch]:
        relative, inside = _relative_posix(action.path, action.project_root)
        matches: list[RuleMatch] = []
        if not relative:
            return matches
        if not inside:
            matches.append(RuleMatch("outside-project", Decision.ASK, Risk.HIGH,
                                     "Path is outside the project directory."))
        if _matches_any(relative, SECURITY_CONTROL_GLOBS):
            matches.append(RuleMatch("security-control-modification" if write else "security-control-read",
                                     Decision.ASK if write else Decision.ALLOW, Risk.HIGH if write else Risk.LOW,
                                     "File is part of the UDS / Claude Code / Git hook security configuration."))
        if _matches_any(relative, CI_GLOBS) and write:
            matches.append(RuleMatch("ci-workflow-modification", Decision.ASK, Risk.MEDIUM,
                                     "CI workflow changes can alter security checks and secret access."))
        name = PurePosixPath(relative).name.lower()
        if _matches_any(relative, SECRET_FILE_GLOBS) and name not in SECRET_FILE_ALLOW:
            matches.append(RuleMatch("secret-file-access", Decision.ASK, Risk.MEDIUM,
                                     "File commonly contains credentials."))
        if self.config.protected_paths and _matches_any(relative, self.config.protected_paths):
            matches.append(RuleMatch("project-protected-path", Decision.ASK, Risk.HIGH,
                                     "Path is protected by project policy.", "project"))
        return [m for m in matches if m.decision is not Decision.ALLOW]

    def _evaluate_write(self, action: Action) -> list[RuleMatch]:
        matches = self._path_matches(action, write=True)
        secrets = find_secrets(action.content)
        if secrets:
            rules = sorted({s.rule_id for s in secrets})
            lines = sorted({s.line for s in secrets})[:10]
            matches.append(RuleMatch("secret-in-file", Decision.DENY, Risk.CRITICAL,
                                     f"Content contains likely credential(s) ({', '.join(rules)}) at line(s) "
                                     f"{', '.join(map(str, lines))}. Store secrets in environment variables or a "
                                     "secret manager instead."))
        return matches

    def _evaluate_read(self, action: Action) -> list[RuleMatch]:
        return self._path_matches(action, write=False)

    def _evaluate_delete(self, action: Action) -> list[RuleMatch]:
        matches = self._path_matches(action, write=True)
        matches.append(RuleMatch("file-delete", Decision.ASK, Risk.MEDIUM, "Deleting files requires approval."))
        return matches


def evaluate(action: Action, config: ProjectConfig | None = None) -> PolicyDecision:
    return PolicyEngine(config).evaluate(action)
