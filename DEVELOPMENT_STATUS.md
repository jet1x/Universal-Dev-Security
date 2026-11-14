# Development Status

**Current version:** `1.0.0rc1` (release candidate — built and verified locally, **not published**)
**Last updated:** 2026-11-14
**Previous version:** 0.4.1 (original source archived at `dist/uds-0.4.1-original-source-backup.zip`, git-ignored)

## Milestones

| # | Milestone | Status | Acceptance evidence |
|---|---|---|---|
| 1 | Core foundation and policy engine | ✅ Complete | `test_policy.py`, `test_config.py`, `test_redaction.py` |
| 2 | Scanner integrations | ✅ Complete (see known issue 1) | `test_scanner.py`; real Gitleaks 8.30.1, OSV-Scanner 2.7.1, Trivy 0.76.2 runs; `test_scanner_fixtures.py` from real output |
| 3 | Unified findings schema and reporting | ✅ Complete | `test_reports.py` (schema, SARIF, escaping, CSP hash, no secrets) |
| 4 | Dark dashboard and scan history | ✅ Complete (see known issue 4) | `test_reports.py`, `test_history.py`, end-to-end CLI test |
| 5 | Claude Code and AI integrations | ✅ Complete (see known issue 3) | `test_integrations.py` (hook decisions, fail-closed, merge/remove, guard protocol) |
| 6 | Git protection and GitHub Actions | ✅ Complete (see known issue 2) | `test_gitguard.py` incl. a real `git commit` blocked by the installed hook; workflow YAML validated |
| 7 | Automatic fixes, testing and recovery | ✅ Complete | `test_recovery_fixes.py` (rollback on failing tests, baseline check, conflict protection) |
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
3. **Claude Code hook not exercised in a live Claude Code session.** The hook protocol is
   implemented per Claude Code's documented `PreToolUse` contract and unit-tested; a live check is
   recommended (`uds integrate claude-code --apply` in a test project). The hook needs `uds` on
   PATH unless `--python-path` is used.
4. **Dashboard not visually reviewed in a browser by the developer agent.** Structure, escaping,
   CSP and well-formedness are tested; a manual visual check is recommended
   (`uds dashboard --open`).
5. `install.sh` is written for Linux/macOS and has not been executed.
6. Python 3.15 is newer than some packages support (PyYAML, Semgrep wheels); UDS itself is
   dependency-free and works on 3.11–3.15.
7. `uds update check --source pypi` will only be meaningful once UDS is published under that name;
   until then use `--source github:OWNER/REPO`.

## Pending decisions (need maintainer approval)

- Publish `1.0.0rc1` (PyPI and/or a GitHub release with `SHA256SUMS`). The source is pushed to
  https://github.com/jet1x/Universal-Dev-Security; no tag or release has been created.
- Enable private vulnerability reporting and secret-scanning push protection on the repository.

## Next development tasks

1. Review the CI self-scan artifact (Semgrep findings) and run the generated workflow in a sample repository.
2. Live-test the Claude Code hook in a sample project.
3. Pin GitHub Actions to commit SHAs in both workflows.
4. Optional offline mode for OSV-Scanner (local databases) to avoid sending package metadata.
5. Hosted web dashboard consuming report schema 2.0 (with authentication and authorization).
