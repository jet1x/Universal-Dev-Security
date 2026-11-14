# Integrations

All integrations are dry runs by default, merge with existing configuration,
create a recovery checkpoint before writing, and can be removed with `--remove`
(which deletes UDS-owned entries only).

## Claude Code

```bash
uds integrate claude-code            # show the planned change to .claude/settings.json
uds integrate claude-code --apply    # merge it (checkpoint created)
uds integrate claude-code --apply --local --python-path   # machine-specific variant in settings.local.json
```

UDS adds a `PreToolUse` hook for `Bash`, `PowerShell`, `Write`, `Edit`,
`MultiEdit`, `NotebookEdit` and `Read`, plus `permissions.ask` rules for
`git push` as defense in depth.

How decisions are returned:

- **No objection:** the hook prints nothing — Claude Code's normal permission flow applies.
  UDS never auto-approves a tool call.
- **Approval required:** `permissionDecision: "ask"` (e.g. `git push`, recursive deletes,
  editing `.uds/`, `.claude/settings*.json`, `.git/hooks`, CI workflows, reading `.env`).
- **Denied:** `permissionDecision: "deny"` (e.g. `--no-verify`, writing likely credentials,
  disabling machine security settings, `rm -rf /`).
- **Fail closed:** malformed input, a broken `.uds/config.toml` or an internal error returns `ask`.

AI tools cannot weaken the policy: changes to UDS, Claude Code and Git hook
configuration require explicit approval, and project configuration can only add rules.

Limitations:

- The default command `uds hook claude-code` requires `uds` on `PATH`. If it is missing the
  hook cannot run, so either keep UDS on `PATH` or use `--python-path`.
- Claude Code runs project hooks only in **trusted** workspaces. Sessions started with
  `CLAUDE_CODE_IGNORE_PERSISTED_TRUST` (for example child sessions launched from inside another
  Claude Code session) do not run them at all. Verify with a harmless test such as asking
  Claude to run `git -C . push` and checking for a `UDS:` message.
- Claude Code protects its own settings files with a built-in safety check that applies before
  UDS; edits to `.claude/settings*.json` therefore always require approval.

Live verification (Claude Code 2.1.323, Windows 11, 2026-11-14): in fresh headless sessions with
the tools pre-allowed, `--no-verify` commits and writes of a fake AWS key were denied with UDS
reasons, `git -C . push`, `rm -rf build` and reading `.env.*` required approval, `git status` ran
untouched, and no blocked action changed the repository. Hooks run through Git Bash on Windows.

## Any other AI agent: `uds guard`

Send one JSON object on stdin; receive a decision on stdout.

```bash
echo '{"action": "shell", "command": "git push origin main"}' | uds guard --project .
```

Request fields: `action` (`shell`, `write_file`, `edit_file`, `read_file`,
`delete_file`, `git_commit`, `git_push`, `publish`), `command`, `path`,
`content`, `project_root`, `actor`.

Response: `{"decision": "allow|ask|deny", "risk": "...", "reason": "...", "matches": [...], "warnings": [...]}`.

Exit codes: `0` allow, `1` ask (obtain explicit user approval), `2` deny,
`3` invalid request. Agents must treat any non-zero exit or unparsable output
as "do not proceed". Responses never contain secret values.

## Git hooks

```bash
uds hooks install --apply                 # pre-commit + pre-push (embeds this interpreter)
uds hooks install --apply --path-only     # rely only on `uds` from PATH
uds hooks status
```

- `pre-commit` scans staged changes; `pre-push` scans outgoing commits (new branches: all
  commits not on the remote). Gitleaks is used when available; otherwise a built-in
  high-confidence pattern set is used and the message says so.
- Hooks fail closed: if UDS cannot run, the commit/push is blocked with instructions.
- With `core.hooksPath` (husky, pre-commit framework) UDS does not modify anything; call
  `uds hook git-pre-commit` and `uds hook git-pre-push "$@"` from your existing hooks.

## GitHub Actions

```bash
uds integrate github --apply --branch main --fail-on high \
  --uds-spec "universal-dev-security @ git+https://github.com/jet1x/Universal-Dev-Security.git@main"
```

Until UDS is published on PyPI, install it from the Git repository as shown (pin a
tag or commit once releases exist).

Generates `.github/workflows/uds-security.yml` which:

- runs on pull requests, pushes to the default branch, and manual dispatch;
- uses `contents: read` plus `security-events: write` only for SARIF upload;
- installs Gitleaks, OSV-Scanner and Trivy from official releases with SHA-256 verification;
- runs `uds scan --require-complete --fail-on <level>` and uploads SARIF (code scanning) and reports.

UDS never commits or pushes the workflow — review and commit it yourself. Also enable
GitHub secret scanning and push protection in repository settings.

## VS Code

```bash
uds integrate vscode --apply
```

Adds tasks *UDS: Security scan*, *UDS: Open dashboard* and *UDS: Doctor* to
`.vscode/tasks.json`. Files containing comments (JSONC) are not modified; add the
tasks manually in that case.
