"""Unified UDS findings schema shared by every scanner adapter and report.

Design rules:

* Severity is only assigned when the source scanner supplies one, or when a
  documented public standard maps the scanner's value (for example the CVSS
  v3 qualitative rating scale). Everything else is ``unclassified``.
* Findings never carry secret values, matched text, or raw scanner output.
* Scanner states distinguish "clean" from "not executed" so a scan is never
  reported as successful when it did not run.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCLASSIFIED = "unclassified"

    @property
    def rank(self) -> int:
        """Higher rank = more severe. Unclassified ranks below low."""
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        """Parse an already-normalized UDS severity label (never a guess)."""
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.UNCLASSIFIED


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNCLASSIFIED: 0,
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNCLASSIFIED]


class ScanStatus(str, Enum):
    CLEAN = "clean"                    # executed, no findings
    FINDINGS = "findings"              # executed, findings returned
    NOT_INSTALLED = "not_installed"    # executable not found
    NOT_APPLICABLE = "not_applicable"  # nothing in the project this scanner covers
    SKIPPED = "skipped"                # deliberately not executed (policy, version, user choice)
    ERROR = "error"                    # attempted but failed

    @property
    def executed(self) -> bool:
        return self in (ScanStatus.CLEAN, ScanStatus.FINDINGS)


class Category(str, Enum):
    SECRET = "secret"
    CODE = "code"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"


def cvss_score_to_severity(score: Any) -> Severity:
    """Map a numeric CVSS v3/v4 base score using the published qualitative scale.

    FIRST CVSS v3.1 specification, section 5: 0.1-3.9 Low, 4.0-6.9 Medium,
    7.0-8.9 High, 9.0-10.0 Critical. 0.0 ("None") and unparsable values are
    left unclassified rather than guessed.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.UNCLASSIFIED
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0.0:
        return Severity.LOW
    return Severity.UNCLASSIFIED


@dataclass
class Finding:
    tool: str
    category: Category
    rule_id: str
    title: str
    file: str = ""
    start_line: int | None = None
    end_line: int | None = None
    severity: Severity = Severity.UNCLASSIFIED
    severity_source: str = "none"      # e.g. "scanner", "cvss-v3-qualitative", "none"
    scanner_severity: str | None = None
    message: str = ""
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    commit: str | None = None
    references: list[str] = field(default_factory=list)
    remediation: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        self.category = Category(self.category)
        self.severity = Severity.parse(self.severity) if not isinstance(self.severity, Severity) else self.severity
        self.start_line = _int_or_none(self.start_line)
        self.end_line = _int_or_none(self.end_line)
        self.file = self.file.replace("\\", "/")
        self.references = list(dict.fromkeys(ref for ref in self.references if _is_http_url(ref)))[:10]
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        # Line numbers are excluded on purpose so moving code does not turn an
        # existing finding into a "new" one when comparing scans.
        basis = "|".join([
            self.tool, self.rule_id, self.file, self.package or "", self.installed_version or "",
        ])
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        allowed = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass
class ScanResult:
    tool: str
    status: ScanStatus
    findings: list[Finding] = field(default_factory=list)
    version: str | None = None
    message: str = ""
    reason: str | None = None
    duration_seconds: float | None = None

    def __post_init__(self) -> None:
        self.status = ScanStatus(self.status)
        if self.status is ScanStatus.CLEAN and self.findings:
            self.status = ScanStatus.FINDINGS
        if not self.status.executed and self.findings:
            raise ValueError("A scanner that did not execute cannot return findings")

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "executed": self.status.executed,
            "version": self.version,
            "message": self.message,
            "reason": self.reason,
            "duration_seconds": self.duration_seconds,
            "finding_count": self.finding_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _is_http_url(value: Any) -> bool:
    return isinstance(value, str) and value.lower().startswith(("https://", "http://")) and len(value) < 2048
