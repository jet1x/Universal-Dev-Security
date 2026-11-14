"""Secret detection heuristics and redaction for text UDS handles itself.

This is *not* a replacement for Gitleaks. It is a small, dependency-free
safety net used where UDS must make a decision without an external scanner,
for example when an AI coding tool is about to write a file or run a command,
and to make sure UDS never echoes likely secrets into logs or reports.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    description: str
    regex: re.Pattern[str]
    group: int = 0


def _p(rule_id: str, description: str, pattern: str, group: int = 0, flags: int = 0) -> SecretPattern:
    return SecretPattern(rule_id, description, re.compile(pattern, flags), group)


# High-confidence, well-documented token formats. Kept conservative to avoid
# blocking legitimate work with false positives.
PATTERNS: tuple[SecretPattern, ...] = (
    _p("private-key", "Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _p("aws-access-key-id", "AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _p("github-token", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"),
    _p("github-fine-grained-pat", "GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"),
    # Every quantifier is bounded: these patterns run on untrusted AI-generated
    # content inside a hook, so catastrophic backtracking (ReDoS) must be impossible.
    _p("gitlab-pat", "GitLab personal access token", r"\bglpat-[A-Za-z0-9_\-]{20,100}\b"),
    _p("slack-token", "Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,200}\b"),
    _p("stripe-secret-key", "Stripe secret key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,200}\b"),
    _p("google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _p("anthropic-api-key", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,300}\b"),
    _p("openai-api-key", "OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,300}\b"),
    _p("npm-token", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("pypi-token", "PyPI upload token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,400}\b"),
    _p("jwt", "JSON Web Token",
       r"\beyJ[A-Za-z0-9_\-]{10,4000}\.eyJ[A-Za-z0-9_\-]{10,8000}\.[A-Za-z0-9_\-]{10,2000}\b"),
    _p(
        "connection-string-password",
        "Credentials embedded in a connection URL",
        r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"]{1,64}:([^\s@/'\"]{6,128})@[^\s'\"]{1,500}",
        group=1,
        flags=re.IGNORECASE,
    ),
    _p(
        "generic-assigned-secret",
        "High-entropy value assigned to a secret-like name",
        r"(?i)\b[\w.\-]{0,40}?(?:secret|passwd|password|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)[\w.\-]{0,40}\s{0,5}[:=]\s{0,5}[\"']?([A-Za-z0-9+/_\-.~]{16,200})[\"']?",
        group=1,
    ),
)

_PLACEHOLDER_HINTS = (
    "example", "placeholder", "changeme", "change_me", "your_", "your-", "xxxx", "dummy",
    "sample", "fake", "test", "redacted", "<", "${", "{{", "process.env", "os.environ", "getenv",
)


@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    description: str
    line: int


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS) or len(set(value)) <= 3


def find_secrets(text: str, *, max_chars: int = 2_000_000) -> list[SecretMatch]:
    """Return locations of likely secrets. Never returns the secret value."""
    if not text:
        return []
    text = text[:max_chars]
    matches: list[SecretMatch] = []
    seen: set[tuple[str, int]] = set()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(pattern.group) or ""
            if pattern.rule_id == "generic-assigned-secret":
                if _looks_like_placeholder(value) or shannon_entropy(value) < 3.5:
                    continue
            elif pattern.rule_id == "connection-string-password" and _looks_like_placeholder(value):
                continue
            line = text.count("\n", 0, match.start()) + 1
            key = (pattern.rule_id, line)
            if key not in seen:
                seen.add(key)
                matches.append(SecretMatch(pattern.rule_id, pattern.description, line))
    return matches


def redact(text: str) -> str:
    """Replace likely secret values in ``text`` with a fixed marker."""
    if not text:
        return text
    result = text
    for pattern in PATTERNS:
        def _replace(match: re.Match[str], pattern: SecretPattern = pattern) -> str:
            value = match.group(pattern.group) or ""
            if pattern.rule_id == "generic-assigned-secret" and (
                _looks_like_placeholder(value) or shannon_entropy(value) < 3.5
            ):
                return match.group(0)
            if pattern.group == 0:
                return REDACTED
            whole = match.group(0)
            start = match.start(pattern.group) - match.start(0)
            end = match.end(pattern.group) - match.start(0)
            return whole[:start] + REDACTED + whole[end:]

        result = pattern.regex.sub(_replace, result)
    return result
