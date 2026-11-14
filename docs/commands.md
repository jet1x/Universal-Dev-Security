# CLI commands

All commands accept an optional project `PATH` (default: current directory).
Commands that modify files are **dry runs unless `--apply` is given**.

## Core

| Command | Purpose |
|---|---|
| `uds --version` | Show the installed version |
| `uds doctor [PATH] [--json]` | Runtime, config validation, scanner versions/compatibility, official install sources |
| `uds detect [PATH]` | Detected technologies, evidence, recommended scanners and Semgrep packs |
| `uds init [PATH]` | Create `.uds/config.toml`, `.uds/README.md`, `.uds/.gitignore` (never overwrites) |
| `uds status [PATH]` | Initialization state and latest scan summary |
| `uds scanners` | Supported scanners with version and install information |

## Scanning and reports

```text
uds scan [PATH] [--tool NAME ...] [--format json,html,sarif] [--report-dir DIR]
                [--allow-network] [--fail-on LEVEL] [--require-complete]
                [--no-history] [--json | --quiet]
```

- `--tool` runs only the named scanner(s): `gitleaks`, `semgrep`, `osv-scanner`, `trivy`.
- `--allow-network` approves OSV-Scanner, which sends package names and versions to osv.dev.
- `--fail-on` (`none|unclassified|low|medium|high|critical`): exit `1` when findings reach the level.
  Once any threshold is set, secret findings always fail the check.
- `--require-complete`: exit `2` if an applicable scanner was not installed or was skipped.

Exit codes: `0` success, `1` findings at/above threshold, `2` scan error, nothing scanned,
incomplete with `--require-complete`, or invalid input.

| Command | Purpose |
|---|---|
| `uds report [PATH] [--scan ID\|latest\|previous] [--format ...]` | Regenerate reports from history |
| `uds dashboard [PATH] [--open]` | Print (and optionally open) the latest HTML dashboard |
| `uds history [PATH] [--json]` | List recorded scans |
| `uds compare [PATH] [--base previous] [--head latest] [--json]` | New / resolved / unchanged / not re-scanned findings |

## Policy and AI agents

| Command | Purpose |
|---|---|
| `uds policy show [PATH]` | Global rules and the effective project policy |
| `uds policy check [PATH] --command "..."` | Evaluate a shell command (exit 0 allow, 1 ask, 2 deny) |
| `uds policy check [PATH] --write FILE [--content-file F]` | Evaluate a file write |
| `uds guard [--project PATH]` | Generic agent protocol: JSON action on stdin (see integrations.md) |
| `uds hook claude-code` | Claude Code `PreToolUse` hook entry point |

## Git protection

| Command | Purpose |
|---|---|
| `uds hooks install [PATH] [--apply] [--path-only]` | Install `pre-commit` and `pre-push` hooks (embed this Python interpreter, with `uds` on PATH as fallback; `--path-only` uses PATH only) |
| `uds hooks uninstall [PATH] [--apply]` | Remove UDS-owned hooks only |
| `uds hooks status [PATH]` | Show hook state (`uds`, `foreign`, `missing`) |
| `uds hook git-pre-commit` / `git-pre-push` | Hook entry points (called by Git) |

Existing non-UDS hooks are never overwritten, and a configured `core.hooksPath`
(husky, pre-commit, …) is respected — UDS prints how to call it from your hook manager.

## Integrations

```text
uds integrate claude-code [PATH] [--apply] [--remove] [--local] [--python-path]
uds integrate github      [PATH] [--apply] [--remove] [--branch main] [--fail-on high] [--uds-spec SPEC]
uds integrate vscode      [PATH] [--apply] [--remove]
```

## Recovery, fixes and tests

| Command | Purpose |
|---|---|
| `uds checkpoint create [PATH] --file F [--file F2] [--label L]` | Snapshot files |
| `uds checkpoint list [PATH]` | List checkpoints |
| `uds rollback ID [PATH] [--force]` | Restore; files edited after the checkpoint are kept unless `--force` |
| `uds fix [PATH]` | Show planned automatic fixes and manual (high-risk) recommendations |
| `uds fix [PATH] --apply [--include-medium] [--skip-tests] [--approve]` | Apply fixes with checkpoint + test verification |
| `uds test [PATH]` | Detect and run the project's test suite |

## Updates

| Command | Purpose |
|---|---|
| `uds update check [--source pypi\|github:OWNER/REPO]` | Report a newer UDS release (network only when a source is given) |
| `uds update scanners` | Installed scanner versions vs. supported minimums |

UDS never installs or upgrades itself or any scanner.
