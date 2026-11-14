# Installation and upgrades

## Install UDS

UDS requires Python 3.11 or newer and has no runtime dependencies.

**Windows (user-level, no administrator rights):**

```powershell
.\scripts\install.ps1 -Wheel .\dist\1.0.0\universal_dev_security-1.0.0-py3-none-any.whl
# optional: add the venv Scripts folder to your *user* PATH
.\scripts\install.ps1 -Wheel <wheel> -AddToPath
```

**Linux / macOS:**

```bash
sh scripts/install.sh --wheel dist/1.0.0/universal_dev_security-1.0.0-py3-none-any.whl
export PATH="$HOME/.local/share/uds/venv/bin:$PATH"
```

The installers create a dedicated virtual environment, verify the wheel against
`SHA256SUMS` when it is present (and abort on mismatch), and never modify system
settings. Shell profiles are never edited; the Windows installer changes the
*user* PATH only with `-AddToPath`.

**From the Git repository (any OS):**

```bash
python -m pip install "universal-dev-security @ git+https://github.com/jet1x/Universal-Dev-Security.git@main"
```

**Development install:**

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"     # Windows: .venv\Scripts\python
.venv/bin/python -m pytest
```

## Install scanners (official sources)

UDS works with any subset of scanners and reports missing ones as `not_installed`.

| Scanner | Windows | macOS | Linux |
|---|---|---|---|
| Gitleaks | `winget install --id Gitleaks.Gitleaks -e` | `brew install gitleaks` | [GitHub releases](https://github.com/gitleaks/gitleaks/releases) + checksum |
| Semgrep | `python -m pip install semgrep` in the UDS venv | `brew install semgrep` | `python3 -m pip install semgrep` |
| OSV-Scanner | `winget install --id Google.OSVScanner -e` or [releases](https://github.com/google/osv-scanner/releases) | `brew install osv-scanner` | [releases](https://github.com/google/osv-scanner/releases) + `osv-scanner_SHA256SUMS` |
| Trivy | `winget install --id AquaSecurity.Trivy -e` | `brew install trivy` | [official repositories](https://trivy.dev/latest/getting-started/installation/) |

Verify with `uds doctor`. A scanner older than the supported minimum is reported
as `skipped` with reason `unsupported_version`.

## Upgrade UDS

1. Check: `uds update check --source github:jet1x/Universal-Dev-Security` (or `--source pypi` once published). This is the
   only command that contacts the network for updates, and only when a source is given.
2. Read the [CHANGELOG](../CHANGELOG.md) for breaking changes.
3. Upgrade inside the UDS virtual environment:
   - from a verified wheel: re-run the installer with the new wheel;
   - from PyPI (once published): `python -m pip install --upgrade universal-dev-security`.
4. Run `uds doctor` and `uds scan`.

Project files (`.uds/config.toml`, history, checkpoints) are compatible across
upgrades. New configuration keys have safe defaults; unknown or invalid values
produce warnings and fall back to defaults.

### Upgrading from 0.4.x

- `uds scan` now prints a human-readable summary; use `--json` for machine output.
- Scan exit codes: `0` success, `1` threshold reached (`--fail-on`), `2` error / nothing scanned.
- The JSON report schema is now `2.0` (multi-scanner, unified findings). The Python
  helpers `scanner.scan_with_gitleaks()` and `scanner.find_gitleaks()` remain available.
- Re-running `uds init` does not modify an existing `.uds/config.toml`. To adopt the new
  sections (`[scanners]`, `[testing]`, `[history]`), copy them from a fresh `uds init` in
  an empty directory.

## Uninstall

Remove UDS-owned integrations first (each is reversible):

```bash
uds hooks uninstall --apply
uds integrate claude-code --remove --apply
uds integrate github --remove --apply
```

Then delete the UDS virtual environment (`%LOCALAPPDATA%\UDS` or
`~/.local/share/uds`) and, if desired, the project's `.uds/` directory.
