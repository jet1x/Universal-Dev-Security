# Security Policy

## Reporting a vulnerability

Please do **not** publish exploitable details in a public issue.

- Preferred: use GitHub **private vulnerability reporting** ("Report a vulnerability" on the
  repository's Security tab) once it is enabled.
- Until then, open a minimal issue asking the maintainers for a private channel. Do not include
  exploit details, credentials or private data.

Please include the affected version, platform, and a minimal reproduction. We aim to acknowledge
reports within 7 days and to agree on a disclosure timeline with the reporter.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (including release candidates) | Yes |
| < 1.0 | No |

## Scope

This policy covers UDS itself: the CLI, policy engine, hooks, integrations, report generation
and installers. Integrated third-party scanners (Gitleaks, Semgrep, OSV-Scanner, Trivy) have
their own security reporting processes.

Particularly relevant classes of issues: secret leakage into output or reports, policy bypasses
that let an AI agent perform an action without the required approval, command injection or
unsafe process execution, path traversal in recovery/history, unsafe HTML in reports, and
denial of service in pattern matching.

See [docs/security-model.md](docs/security-model.md) for guarantees and known limitations.
