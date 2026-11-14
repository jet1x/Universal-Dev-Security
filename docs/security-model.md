# Security model

UDS follows least privilege, explicit consent, and honest reporting.

## Guarantees

- **No telemetry.** The core makes no network requests. `uds update check` contacts a source
  only when one is given explicitly (HTTPS only, including redirects; GET only).
- **Scanner network use is disclosed** in every report. OSV-Scanner, which sends package names
  and versions to osv.dev, runs only with `--allow-network` or `allow_network = true`.
- **No secrets in output.** Gitleaks runs with `--redact`; adapters copy only metadata; scanner
  messages are redacted; raw stdout/stderr is never printed or stored.
- **Safe execution.** Scanners run with argument lists, `shell=False`, closed stdin, timeouts,
  and validated executables. Windows `.bat`/`.cmd` scanner wrappers are refused.
- **No silent changes.** File-changing commands are dry runs by default; `--apply` creates a
  checkpoint first and writes atomically. Invalid or foreign configuration is left untouched.
- **Reversible.** `uds rollback` restores UDS changes and refuses to overwrite files the user
  edited afterwards (unless `--force`).
- **No global changes.** UDS does not install software, change machine security settings,
  modify global Git configuration, commit, push, or publish.
- **Policy cannot be weakened** by project configuration or AI tools (see `policy.py`).
- **Fail closed.** Git hooks and the Claude Code hook block / require approval when UDS cannot
  evaluate an action.
- **Safe reports.** All HTML values are escaped, links are limited to http(s), embedded JSON
  cannot terminate its script block, and a Content-Security-Policy permits only the report's
  own script (by SHA-256 hash) with no external resources.
- **Bounded analysis.** Secret and command patterns use bounded quantifiers (ReDoS-safe);
  commands over 20,000 characters require approval instead of being analyzed.

## Trust boundaries and limitations

- **Repository content is trusted to the same degree as running its tests.** `uds test` and
  `uds fix` execute the project's test command (from `.uds/config.toml` or auto-detected).
  Only run them on repositories you trust. Scanning (`uds scan`) does not execute project code.
- A repository's own `.gitleaks.toml` and `.uds/config.toml` are honored; review them in
  untrusted repositories (a project config can opt in to OSV-Scanner network use).
- Local hooks can be bypassed (`git commit --no-verify`, deleting hooks). They are defense in
  depth; use CI scanning and repository push protection as independent controls.
- The Claude Code hook requires `uds` to be runnable; if Claude Code cannot start the hook
  command, it cannot enforce anything. Use `--python-path` to avoid PATH dependence.
- Built-in secret patterns (used when Gitleaks is unavailable and for AI-agent decisions) are a
  conservative safety net, not a replacement for Gitleaks.
- A clean scan means only that the executed scanners found nothing.
