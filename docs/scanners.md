# Scanners, severity and privacy

## Supported scanners

| Scanner | Category | Minimum | Verified with | Applies when | Network behavior |
|---|---|---|---|---|---|
| Gitleaks | Secrets | 8.19.0 (`gitleaks dir`) | 8.30.1 (real binary) | Always | Fully offline |
| Semgrep | Code (SAST) | 1.0.0 | Fixtures only (see DEVELOPMENT_STATUS) | Source code present | Downloads registry rule packs; UDS forces `--metrics=off`; source is not uploaded |
| OSV-Scanner | Dependencies | 1.4.0 (v1 and v2 CLI) | 2.7.1 (real binary) | Manifests/lockfiles present | **Sends package names + versions to osv.dev** — requires `--allow-network` or `allow_network = true` |
| Trivy | Dependencies + misconfiguration | 0.45.0 | 0.76.2 (real binary) | Manifests or Docker/IaC files present | Downloads vulnerability DB and checks; files analysed locally |

UDS locates scanners on `PATH`, then in well-known per-user locations (the UDS
virtual environment, WinGet links/packages, Scoop, Homebrew, `~/.local/bin`,
`~/go/bin`). `UDS_GITLEAKS_PATH`, `UDS_SEMGREP_PATH`, `UDS_OSV_SCANNER_PATH` and
`UDS_TRIVY_PATH` override discovery. On Windows, `.bat`/`.cmd` wrappers are
refused because `cmd.exe` argument quoting cannot be made fully safe.

Official installation sources are printed by `uds doctor`. UDS never installs scanners.

## Scanner states

| State | Meaning |
|---|---|
| `clean` | Executed; no findings |
| `findings` | Executed; findings returned |
| `not_installed` | Executable not found (or only an unsafe wrapper found) |
| `not_applicable` | Nothing in the project this scanner covers |
| `skipped` | Deliberately not executed: unsupported/unknown version or network not approved |
| `error` | Attempted but failed (exit code, timeout, unparsable output) — raw output is suppressed |

Overall status: `findings` > `error` > `incomplete` (an applicable scanner did
not run) > `clean`; `not_scanned` when nothing executed.

## Severity — never invented

| Source | Mapping | `severity_source` |
|---|---|---|
| Trivy | Native `CRITICAL/HIGH/MEDIUM/LOW`; `UNKNOWN` → unclassified | `scanner` |
| Semgrep | Native `CRITICAL/HIGH/MEDIUM/LOW`; legacy `ERROR/WARNING/INFO` → high/medium/low as documented by Semgrep | `scanner` |
| OSV-Scanner | Group `max_severity` CVSS base score → FIRST CVSS qualitative scale (0.1–3.9 low, 4.0–6.9 medium, 7.0–8.9 high, 9.0–10 critical) | `cvss-qualitative-scale` |
| OSV-Scanner fallback | GitHub Advisory Database severity (`MODERATE` → medium) when no CVSS score exists | `advisory-database` |
| Gitleaks | No validated severity exists → `unclassified` | `none` |

The original scanner value is kept in `scanner_severity`. No numeric security score is produced.

## Unified finding schema

`tool, category (secret|code|dependency|configuration), rule_id, title, file,
start_line, end_line, severity, severity_source, scanner_severity, message,
package, installed_version, fixed_version, commit, references (http/https only,
deduplicated), remediation, fingerprint`.

Fingerprints exclude line numbers so moved code is not reported as new. Secret
values, matched text, source lines and raw scanner output are never stored.

## Exclusions

Third-party and generated directories (`node_modules`, `.venv`, `site-packages`,
caches, `.uds/reports|history|backups`) are excluded. For secret scanning,
`dist/` and `build/` are deliberately **still scanned** because bundles often
leak credentials. A project `.gitleaks.toml` takes precedence over UDS defaults.
Add exclusions with `[scanners] exclude_paths`.

## Adding a scanner

Subclass `universal_dev_security.scanners.base.ScannerAdapter`, implement
`applicable()` and `execute()` (use `run_tool()`; never log raw output), return
normalized `Finding` objects, and register it with
`universal_dev_security.scanners.register_scanner()`. Add fixture-based tests
for the output format and state handling.
