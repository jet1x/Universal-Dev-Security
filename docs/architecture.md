# Architecture

UDS is a dependency-free Python package built from small, independently tested
modules. External scanners are adapters behind one interface and can be
replaced or extended.

```
                 ┌──────────── cli.py / cli_extra.py ────────────┐
                 │                                                │
   config.py ──► policy.py ◄── integrations/ (claude_code, agents guard, github, vscode)
       │             ▲                        gitguard.py (pre-commit / pre-push)
       ▼             │
   detector.py ─► engine.py ──► scanners/ (base, gitleaks, semgrep, osv, trivy)
   projectfiles.py   │                 └─ run_tool(): argv list, no shell, timeout, no raw output
                     ▼
               findings.py (unified schema, states, CVSS scale)
                     │
          history.py ─┼─► reports.py (JSON, SARIF, HTML dashboard)
                     │
   recovery.py ◄── fixes.py ──► testing.py        updates.py (explicit, HTTPS-only checks)
```

## Modules

| Module | Responsibility |
|---|---|
| `config` | Parse `.uds/config.toml`; only accept restrictions; warn on attempts to weaken mandatory settings |
| `policy` | Immutable global rules + project additions → `allow` / `ask` / `deny` with risk and reasons |
| `redaction` | Bounded (ReDoS-safe) secret patterns for UDS's own decisions and output redaction |
| `projectfiles`, `detector` | Bounded, symlink-safe inventory; technology detection with evidence; scanning profiles |
| `scanners/*` | Discovery, version/compatibility checks, applicability, execution and normalization |
| `engine` | Orchestration, honest overall status, exit codes and fail-on thresholds |
| `findings` | Severity, scanner states, categories, `Finding`/`ScanResult`, CVSS qualitative scale |
| `history` | Scan history, pruning, safe id resolution, comparison that never marks unscanned findings resolved |
| `reports` | Recommendations, SARIF 2.1.0, self-contained HTML dashboard with hash-based CSP |
| `recovery` | Checkpoints, atomic writes, rollback that protects later user edits |
| `fixes`, `testing` | Risk-tiered automatic fixes verified by the project's tests |
| `gitguard` | Hook installation (never overwriting foreign hooks) and hook runtime |
| `integrations` | Claude Code hooks, generic `uds guard` protocol, GitHub workflow, VS Code tasks |
| `updates` | Explicit update checks (no auto-update) and scanner version status |

## Policy precedence

1. Mandatory UDS global policy (`policies/GLOBAL_SECURITY_POLICY.md`, enforced in `policy.py`).
2. Technology profile (scanner selection and rule packs).
3. Project configuration (`.uds/config.toml`) — may add deny/approval rules and protected
   paths; cannot remove rules, disable Gitleaks, or turn off mandatory approvals.

## Future web dashboard

The JSON report (schema `2.0`) is the contract between the scan engine and any
presentation layer. A future hosted dashboard should consume the same schema and
reuse the tokens in `docs/dashboard-design-system.md`, adding authentication,
authorization, CSRF protection and server-side validation before handling
remote projects.
