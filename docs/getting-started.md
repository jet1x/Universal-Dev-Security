# Getting started

This guide takes you from installation to a protected project in about ten minutes.
UDS runs locally: it checks your project with established security scanners, shows the
results in one dashboard, and can stop mistakes such as committing a password before they
happen.

## 1. Install UDS

You need Python 3.11 or newer.

```bash
python -m pip install universal-dev-security
```

Check what is available on your machine:

```bash
uds doctor
```

```text
UDS 1.0.1 · Python 3.12.4 · Windows 11
Git available: yes
Project config: not initialized
Scanners:
  Gitleaks     OK 8.30.1
  Semgrep      not installed
               install: python -m pip install semgrep  (inside the UDS virtual environment)
  OSV-Scanner  not installed
               install: winget install --id Google.OSVScanner -e  or download from https://github.com/google/osv-scanner/releases
  Trivy        not installed
               install: winget install --id AquaSecurity.Trivy -e
UDS runtime: OK (no network access used, no global settings modified)
```

## 2. Install the scanners you want

UDS never installs software for you. `uds doctor` prints the official install command for
your operating system. What each scanner adds:

| Scanner | Finds | Recommended |
|---|---|---|
| **Gitleaks** | Passwords, API keys and tokens in your files | **Yes — the minimum** |
| Semgrep | Risky code patterns (injection, unsafe functions, …) | Yes |
| Trivy | Vulnerable libraries and insecure Docker / Kubernetes / Terraform configuration | Yes |
| OSV-Scanner | Vulnerable libraries (a second, independent database) | Optional — sends package names and versions to osv.dev, so it only runs when you allow network use |

Run `uds doctor` again afterwards; installed scanners show `OK`.

## 3. Scan a project

```bash
cd path/to/your-project
uds scan
```

```text
UDS scan 20261114T121420244950Z-edd0df · path/to/your-project
Overall status: FINDINGS
  gitleaks     clean               0  No findings reported by Gitleaks.
  semgrep      not_installed       -  Semgrep was not found. See https://semgrep.dev/docs/getting-started/quickstart ...
  osv-scanner  not_installed       -  OSV-Scanner was not found. See https://google.github.io/osv-scanner/installation/ ...
  trivy        findings            9  9 finding(s) reported by Trivy.
Findings: critical 0, high 3, medium 6, low 0, unclassified 0 (total 9)
Report (json): path/to/your-project/.uds/reports/security-report.json
Report (html): path/to/your-project/.uds/reports/security-report.html
```

What happened:

1. UDS detected the project's technologies (Python, Next.js, Docker, …).
2. It ran only the scanners that apply to them, and says clearly which ones did not run.
3. It wrote a JSON report and an HTML dashboard to `.uds/reports/` (excluded from Git).

To include OSV-Scanner, approve its network use explicitly: `uds scan --allow-network`.

## 4. Read the results

```bash
uds dashboard --open
```

The dashboard opens in your browser (it works offline and loads nothing from the internet):

- **Findings by severity** — critical, high, medium, low, and *unclassified* when the scanner
  gives no severity. UDS never invents a severity or a "security score".
- **Recommendations** — what to do first, for example *"Upgrade jinja2 → 2.10.1"* or
  *"Rotate 1 credential found in Git-tracked files"*.
- **Findings** — search and filter; open a finding to see the file, line, explanation, fix and
  references. Secrets are marked **in Git** (already shared — rotate them) or **local only**.
- **Change since previous scan** — what is new and what was fixed since your last `uds scan`.

Secret values are never shown — only the file and line where they are.

## 5. Fix what was found

- **Vulnerable library:** upgrade it to the version shown, then run your tests (`uds test`).
- **Secret in a file:** move it to an environment variable or a secret manager. If it was ever
  committed or shared, also **revoke or rotate it** with the service that issued it.
- **Code or configuration issue:** follow the remediation shown in the finding.

UDS can apply a few safe fixes itself, such as adding `.env` files to `.gitignore`:

```bash
uds fix            # shows what it would change
uds fix --apply    # applies it, runs your tests, and undoes the change if they fail
```

Then run `uds scan` again to confirm.

## 6. Prevent new problems

### Block secrets before they reach Git

```bash
uds hooks install --apply
```

From now on a commit that contains a secret is stopped:

```text
$ git commit -m "add settings"
UDS: 1 potential secret(s) found in staged changes (Gitleaks). Blocked.
  - generic-api-key: settings.py:1
UDS: remove the secret, rotate it if it was ever pushed, and use environment variables or a secret manager.
```

Pushes are checked the same way. Existing Git hooks are never overwritten.

### Keep AI coding assistants within safe limits (Claude Code)

```bash
uds integrate claude-code --apply
```

Claude Code will then ask for your approval before `git push`, recursive deletes or reading
`.env` files, and is blocked from writing credentials into files or bypassing Git hooks with
`--no-verify`. Restart Claude Code after installing. Other agents can use the same policy
through `uds guard` (see [integrations](integrations.md)).

### Check every pull request on GitHub

```bash
uds integrate github --apply
```

This creates `.github/workflows/uds-security.yml`. Review it and commit it yourself — UDS never
commits or pushes. Findings appear in the repository's *Security → Code scanning* tab.

## Safety rules UDS follows

- **Nothing changes without your say.** Commands that modify files show a preview first and
  change something only with `--apply`.
- **Everything can be undone.** Each change creates a recovery point: `uds rollback <id>`.
- **Honest results.** A scanner that did not run is reported as such; a clean result means only
  that the scanners that ran found nothing.
- **Private by default.** No telemetry; nothing leaves your machine unless you allow it.

## Command cheat sheet

| I want to… | Command |
|---|---|
| See what is installed | `uds doctor` |
| Scan the project | `uds scan` |
| Open the results | `uds dashboard --open` |
| Compare with the previous scan | `uds compare` |
| Apply safe fixes | `uds fix --apply` |
| Block secrets in commits and pushes | `uds hooks install --apply` |
| Protect work with Claude Code | `uds integrate claude-code --apply` |
| Check every pull request | `uds integrate github --apply` |
| Undo a change made by UDS | `uds rollback <id>` |
| Fail a CI job on serious findings | `uds scan --fail-on high` |

Next: [all commands](commands.md) · [scanners and severity](scanners.md) ·
[integrations](integrations.md) · [security model](security-model.md)
