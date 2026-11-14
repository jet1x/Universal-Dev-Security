# Universal Dev Security (UDS)

**One Security System. Every Project.**

UDS is an open-source, local-first security toolkit for developers. It runs
industry-standard scanners on any project, normalizes their results into one
schema, enforces a central security policy for Git and AI coding agents, and
produces a dark, self-contained HTML security dashboard.

> **Status:** `1.0.0` — first stable release. See
> [DEVELOPMENT_STATUS.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/DEVELOPMENT_STATUS.md) for verified functionality,
> known issues and test results. UDS reports what its scanners find; a clean
> result is never proof that a project is secure.

## What it does

| Area | Capability |
|---|---|
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) directory, staged and outgoing-commit scanning (values always redacted) |
| Code | [Semgrep](https://semgrep.dev) static analysis with technology-based rule packs (metrics disabled) |
| Dependencies | [OSV-Scanner](https://google.github.io/osv-scanner/) and [Trivy](https://trivy.dev) vulnerability scanning |
| Configuration | Trivy misconfiguration scanning (Dockerfile, Kubernetes, Terraform, …) |
| Policy | Central engine: approval for `git push`, denial of hook bypasses and secret writes, project rules can only add restrictions |
| Git | `pre-commit` / `pre-push` hooks that block secrets (fail closed) |
| AI agents | Claude Code `PreToolUse` hooks; generic `uds guard` JSON protocol for any agent |
| GitHub | Generated PR workflow with checksum-verified scanners and SARIF upload |
| Reports | JSON, SARIF 2.1.0 and an offline dark HTML dashboard with filters, history and scan comparison |
| Recovery | Checkpoints before every UDS change; rollback that never clobbers later user edits |
| Fixes | Low-risk, reversible fixes verified by your test suite, rolled back automatically if tests fail |

Scanner states are explicit — `clean`, `findings`, `not_installed`,
`not_applicable`, `skipped`, `error` — and the overall status becomes
`incomplete` when an applicable scanner did not run. Severity is shown only
when the scanner supplies it or a published scale (CVSS) defines it; everything
else is `unclassified`. No security score is invented.

## Quick start

New to UDS? The **[Getting started guide](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/getting-started.md)**
walks through installation, your first scan, reading the dashboard, fixing findings and turning
on protection, with real example output.

Requirements: Python 3.11+, Windows, Linux or macOS. Git is recommended.

```bash
python -m pip install universal-dev-security
```

The package on [PyPI](https://pypi.org/project/universal-dev-security/) is identical to the
assets of the [GitHub release](https://github.com/jet1x/Universal-Dev-Security/releases)
(same SHA-256). Prefer an isolated install? Use `pipx install universal-dev-security`, or the
checksum-verifying installers described in
[docs/installation.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/installation.md).

Install at least [Gitleaks](https://github.com/gitleaks/gitleaks#installing); `uds doctor`
shows the official install command for every scanner. Then, inside a project:

```bash
uds doctor                 # runtime, config and scanner availability (+ official install sources)
uds init                   # create .uds/config.toml (never overwrites)
uds scan                   # run applicable scanners, write JSON + HTML reports, record history
uds dashboard --open       # open the dark HTML dashboard
uds hooks install --apply  # block secrets at commit and push time
uds integrate claude-code --apply   # enforce the UDS policy inside Claude Code
```

Every command that changes files is a **dry run by default** and shows a diff;
`--apply` creates a recovery checkpoint first. See [docs/installation.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/installation.md)
for scanner installation and upgrades, and [docs/commands.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/commands.md) for all commands.

## Documentation

- [Getting started](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/getting-started.md)
- [Installation and upgrades](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/installation.md)
- [Commands](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/commands.md)
- [Scanners, severity and privacy](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/scanners.md)
- [Integrations: Claude Code, GitHub, VS Code, other agents](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/integrations.md)
- [Architecture](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/architecture.md)
- [Security model](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/security-model.md) and [global policy](https://github.com/jet1x/Universal-Dev-Security/blob/main/policies/GLOBAL_SECURITY_POLICY.md)
- [Dashboard design system](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/dashboard-design-system.md)
- [Release process](https://github.com/jet1x/Universal-Dev-Security/blob/main/docs/release.md)

## Safety guarantees

- No telemetry. The core never contacts the network; scanners' network use is documented and
  OSV-Scanner (which sends package names/versions to osv.dev) runs only with explicit approval.
- UDS never installs scanners, never commits, never pushes and never publishes.
- Existing configuration is merged, never silently overwritten; invalid files are left untouched.
- Secret values, matched text and raw scanner output never appear in output, reports or history.
- Global policies cannot be weakened by project configuration or AI tools.

Local Git hooks and AI-agent hooks are defense in depth — keep CI scanning and
repository-level protections (for example GitHub push protection) enabled too.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/CONTRIBUTING.md) and [SECURITY.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/SECURITY.md).
Changes are listed in [CHANGELOG.md](https://github.com/jet1x/Universal-Dev-Security/blob/main/CHANGELOG.md).

## License

Apache License 2.0. See [LICENSE](https://github.com/jet1x/Universal-Dev-Security/blob/main/LICENSE).
