# Development Status

**Current version:** `1.0.0rc1` — published as a GitHub pre-release (tag `v1.0.0rc1`, assets checksum-verified after upload). `main` contains unreleased improvements (see CHANGELOG).
**Last updated:** 2026-11-14
**Previous version:** 0.4.1 (original source archived at `dist/uds-0.4.1-original-source-backup.zip`, git-ignored)

## Milestones

| # | Milestone | Status | Acceptance evidence |
|---|---|---|---|
| 1 | Core foundation and policy engine | ✅ Complete | `test_policy.py`, `test_config.py`, `test_redaction.py` |
| 2 | Scanner integrations | ✅ Complete (see known issue 1) | `test_scanner.py`; real Gitleaks 8.30.1, OSV-Scanner 2.7.1, Trivy 0.76.2 runs; `test_scanner_fixtures.py` from real output |
| 3 | Unified findings schema and reporting | ✅ Complete | `test_reports.py` (schema, SARIF, escaping, CSP hash, no secrets) |
| 4 | Dark dashboard and scan history | ✅ Complete (see known issue 4) | `test_reports.py`, `test_history.py`, end-to-end CLI test |
| 5 | Claude Code and AI integrations | ✅ Complete — live-verified | `test_integrations.py`; live Claude Code 2.1.323 sessions (see test results) |
| 6 | Git protection and GitHub Actions | ✅ Complete (see known issue 2) | `test_gitguard.py` incl. a real `git commit` blocked by the installed hook; workflow YAML validated |
| 7 | Automatic fixes, testing and recovery | ✅ Complete | `test_recovery_fixes.py`; real rollback used to remove the integration from a real project without conflicts |
| 8 | Technology profiles and compatibility | ✅ Complete | `test_detector.py` (17 technologies, nested projects, exclusions) |
| 9 | Installer, updates and release management | ✅ Complete | `scripts/release.py` run end-to-end; `install.ps1` install + tampered-checksum rejection tested |
| 10 | Cross-platform compatibility | ✅ Complete | GitHub Actions run 43534444713: all 12 matrix jobs (Windows/Linux/macOS × Python 3.11–3.14) passed |
| 11 | Production readiness / release preparation | ✅ RC prepared — awaiting approval | Security audit below; artifacts in `dist/1.0.0rc1/` |

## Test results (actually executed)

| Environment | Result |
|---|---|
| Windows 11, Python 3.15.2 (project `.venv`) | **196 passed, 1 skipped** (PyYAML has no Python 3.15 wheel; YAML test skipped) |
| Windows 11, Python 3.14.7 (separate tools venv) | **197 passed** |
| Real Gitleaks 8.30.1 | Integration tests ran (directory scan, staged, outgoing commits, hook end-to-end) |
| Real OSV-Scanner 2.7.1 / Trivy 0.76.2 | Run through UDS on a sample vulnerable project: 29 and 16 findings, correctly normalized |
| `scripts/release.py` | Tests ✓, self-scan ✓, sdist+wheel ✓, SHA256SUMS ✓, fresh-venv install + CLI smoke test ✓ |
| `scripts/install.ps1` | Installs with checksum verification ✓; tampered checksum rejected, nothing installed ✓ |
| Self-scan (`uds scan . --allow-network`) | Gitleaks, OSV-Scanner, Trivy: clean. Semgrep: not run (known issue 1) → status `incomplete` |
| Live scan of a real Next.js project (maintainer's own) | All scanners except Semgrep ran; 0 secrets in Git-tracked files; dashboard reviewed visually by the maintainer. Revealed 4 issues (noise from `.next` caches, alarmist rotation advice for local-only secrets, severity ordering, misleading `0` for scanners that did not run) and a 5th (scope changes shown as "resolved") — all fixed with regression tests (`test_exposure.py`) |
| Live Claude Code hook test (2.1.323, headless sessions in a throwaway repo, tools pre-allowed) | `git status` untouched; `git commit --no-verify` **denied** (`UDS: [git-hook-bypass]`); Write of a fake AWS key **denied** (`UDS: [secret-in-file]`, value not echoed); `git -C . push`, `rm -rf build`, Read `.env.*` **required approval** with UDS reasons; `git push` also stopped by the UDS `permissions.ask` rule; edits to `.claude/settings.local.json` stopped by Claude Code's own safety check first. No blocked action changed the repository. Pre-flight: hook command 16/16 in Git Bash and cmd. Finding: project hooks do not run in sessions with `CLAUDE_CODE_IGNORE_PERSISTED_TRUST` (documented) |
| GitHub Actions (commit 760cf4b) | **13/13 jobs passed**: Windows, Ubuntu, macOS × Python 3.11, 3.12, 3.13, 3.14, plus the real-scanner job (Gitleaks 8.30.1, OSV-Scanner 2.7.1, Trivy 0.76.2, Semgrep from PyPI; tests + `uds doctor` + self-scan with `--allow-network --fail-on high`) |

## Security audit (1.0.0rc1)

| Check | Result |
|---|---|
| Exposed credentials / hardcoded secrets | Gitleaks clean on the repository; test secrets are assembled at runtime |
| Unsafe subprocess execution | Two call sites, both argument lists with `shell=False`, validated executables, timeouts; `.bat/.cmd` scanners refused |
| Command injection | Hook scripts embed only allow-listed interpreter paths; workflow generator validates every input; Git ranges/remotes validated |
| Path traversal | Recovery, history and scan ids validated; identical rejection rules on all OSes (fixed during audit) |
| Unsafe automatic fixes | Low risk only by default; checkpoint + baseline/post-change tests + automatic rollback |
| Dependency vulnerabilities | No runtime dependencies; OSV-Scanner and Trivy clean on the repository |
| Insecure report generation | Escaping, http(s)-only links, script-safe embedded JSON, hash-based CSP, no external resources |
| Missing permission checks | Mandatory policy settings cannot be disabled; security-control files require approval |
| Incomplete error handling | Fail-closed hooks; scanner errors become `error` state with suppressed output |
| **Found and fixed:** ReDoS | Unbounded regexes took > 10 minutes on crafted input; now < 1 s (regression tests in `test_redos.py`) |
| **Found and fixed:** HTTPS downgrade | Update check could follow redirects to HTTP; redirects are now HTTPS-only |

## Known issues

1. **Semgrep verified in CI only.** Semgrep could not be installed locally (PyPI network errors).
   In CI it was installed and the self-scan (which runs Semgrep on this Python repository and fails
   on scanner errors or high findings) passed. Its detailed output was not reviewed locally because
   job logs and artifacts require GitHub authentication.
2. **Generated user workflow not yet run on GitHub.** The project's own CI ran green; the
   `uds integrate github` template is YAML-validated and mirrors the CI install steps, but has not
   been run in a user repository.
3. **Claude Code hook: live-verified in headless sessions only.** Interactive approval prompts were
   not exercised (headless mode turns "ask" into a denial). The hook needs `uds` on PATH unless
   `--python-path` is used, and runs only in workspaces Claude Code trusts.
4. ~~Dashboard not visually reviewed~~ — reviewed by the maintainer on a real project (2026-11-14).
5. `install.sh` is written for Linux/macOS and has not been executed.
6. Python 3.15 is newer than some packages support (PyYAML, Semgrep wheels); UDS itself is
   dependency-free and works on 3.11–3.15.
7. `uds update check --source pypi` will only be meaningful once UDS is published under that name;
   until then use `--source github:OWNER/REPO`.

## Pending decisions (need maintainer approval)

- Final `1.0.0` release (1.0.0rc1 is a GitHub pre-release; all release-candidate checks are now done).
- PyPI publication (not done).
- Private vulnerability reporting is enabled (verified via API); secret-scanning push protection
  was enabled by the maintainer but cannot be verified without repository-admin authentication.

## Next development tasks

1. Review the CI self-scan artifact (Semgrep findings) and run the generated workflow in a sample repository.
2. Exercise the interactive Claude Code approval prompt once (headless verification is done).
3. Pin GitHub Actions to commit SHAs in both workflows.
4. Optional offline mode for OSV-Scanner (local databases) to avoid sending package metadata.
5. Hosted web dashboard consuming report schema 2.0 (with authentication and authorization).
