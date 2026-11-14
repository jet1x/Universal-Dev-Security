# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
Semantic Versioning (PEP 440 pre-release suffixes).

## [Unreleased]

Improvements from the first live scan of a real Next.js project.

### Added
- Secret findings record Git exposure (`tracked_in_git`): committed and shared, or local only.
  Recommendations and the dashboard (`in Git` / `local only` tags) distinguish them; only
  committed or unknown secrets are reported as urgent rotations.
- Scan comparisons warn when the scan scope (exclusions) changed, because findings shown as
  "resolved" may have been excluded rather than fixed (`scope_fingerprint`).

### Changed
- Findings are ordered by priority: committed secrets first, then severity (critical → unclassified).
- Secret scanning excludes framework caches and dev-server builds (`.next/cache`, `.next/dev`,
  `.turbo`, `.parcel-cache`, `.angular/cache`); deployable output (`.next/static`,
  `.next/server`) is still scanned. On the test project this removed 97% of noise (708 → 29).

### Fixed
- The scanner coverage table showed `0` findings for scanners that did not run; it now shows `—`.

## [1.0.0rc1] — 2026-11-14 (GitHub pre-release)

### Added
- **Policy engine** (`policy.py`): immutable global rules returning allow / ask / deny with risk
  and reasons; project configuration can only add restrictions; strict mode; `uds policy show|check`.
- **Configuration loader** with validation and warnings; mandatory settings cannot be disabled;
  Gitleaks cannot be disabled.
- **Scanner adapters** for Semgrep, OSV-Scanner (v1 and v2 CLI) and Trivy alongside Gitleaks, with
  executable discovery, version detection, compatibility checks, applicability detection, and the
  states clean / findings / not_installed / not_applicable / skipped / error.
- **Unified findings schema** with severity provenance (`severity_source`), CVSS qualitative scale
  mapping, stable fingerprints and http(s)-only references.
- **Reports:** JSON schema 2.0, SARIF 2.1.0, and a redesigned dark dashboard with severity cards,
  recommendations, scanner coverage, privacy notes, searchable/filterable finding details,
  scan history, scan comparison and JSON/HTML export; hash-based Content-Security-Policy.
- **Scan history and comparison** (`uds history`, `uds compare`, `uds report`, `uds dashboard`).
- **Technology detection** for Python, JavaScript, TypeScript, Node.js, React, Next.js, PHP,
  WordPress, WooCommerce, Java, .NET, Go, Rust, Ruby, Docker, Terraform and Kubernetes, with
  evidence and scanner/rule-pack profiles; nested projects supported.
- **Git protection:** `uds hooks install|uninstall|status`; fail-closed pre-commit and pre-push
  hooks using Gitleaks with a built-in fallback; foreign hooks and `core.hooksPath` respected.
- **Claude Code integration:** `PreToolUse` hook (Bash, PowerShell, Write, Edit, MultiEdit,
  NotebookEdit, Read) that never auto-approves and fails closed; settings merge/removal.
- **Generic agent protocol:** `uds guard` (JSON in, decision out, documented exit codes).
- **GitHub integration:** generated least-privilege PR workflow with checksum-verified scanners
  and SARIF upload. **VS Code** tasks integration.
- **Recovery engine:** checkpoints, atomic writes, rollback that preserves later user edits.
- **Automatic fixes:** risk-tiered, reversible, verified by baseline and post-change test runs
  with automatic rollback. **Testing engine** for pytest, npm, .NET, Maven, Gradle, Go, Cargo, PHPUnit.
- **Update manager:** explicit, HTTPS-only update checks; scanner version status.
- **Release tooling:** `scripts/release.py`, user-level installers with checksum verification
  (`scripts/install.ps1`, `scripts/install.sh`).
- Cross-platform CI matrix (Windows, Linux, macOS × Python 3.11–3.14) and a real-scanner job.

### Changed
- `uds scan` runs all enabled, applicable scanners and prints a readable summary (`--json` for
  machine output). Exit codes: 0 success, 1 threshold reached, 2 error / not scanned.
- Reports use project-relative paths and are written with LF line endings.
- `pyproject.toml` uses an SPDX license expression and a single-sourced version.

### Fixed
- .NET projects were never detected (`.sln`/`.csproj` were compared with whole file names).
- Scan and checkpoint ids now include microseconds so rapid successive scans keep their order.
- Security audit: unbounded regular expressions allowed catastrophic backtracking (ReDoS) on
  crafted input; all patterns are now bounded and oversized commands require approval.

### Security
- Raw scanner output and secret values never reach output, reports, history or hook messages.
- Windows batch-file scanner wrappers are refused (argument injection risk).

## [0.4.1] and earlier

No changelog was kept before 1.0.0rc1. Version 0.4.1 provided the CLI (`doctor`, `detect`,
`init`, `status`, `scan`), marker-based detection, safe initialization, the global policy
document, a Gitleaks directory-scan adapter, sanitized JSON reports and the dark HTML report.
