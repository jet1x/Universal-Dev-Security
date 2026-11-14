# Release process

Releases are built and verified locally. Publishing and pushing always require
explicit maintainer approval and are never performed by UDS tooling.

## Build a release candidate

```bash
python -m pip install build
python scripts/release.py
```

`scripts/release.py`:

1. runs the full test suite (aborts on failure);
2. scans the repository with UDS + Gitleaks (aborts on any finding);
3. builds the sdist and wheel into `dist/<version>/`;
4. writes `SHA256SUMS` and `release-manifest.json`;
5. installs the wheel into a fresh virtual environment and smoke-tests `uds --version` and `uds doctor`.

## Checklist before publishing (requires approval)

- [ ] `DEVELOPMENT_STATUS.md` and `CHANGELOG.md` updated; version bumped in `src/universal_dev_security/__init__.py`.
- [ ] CI green on Windows, Linux and macOS (`.github/workflows/tests.yml`), including the real-scanner job.
- [ ] `uds scan . --allow-network` on the repository reviewed.
- [ ] Artifacts and `SHA256SUMS` attached to a signed Git tag.
- [ ] Private vulnerability reporting enabled on the repository (see SECURITY.md).

## Publish to PyPI (Trusted Publishing)

PyPI publication uses OIDC Trusted Publishing — no API token exists anywhere.

One-time setup on PyPI (account with 2FA): *Your account → Publishing → Add a new pending
publisher* with project `universal-dev-security`, owner `jet1x`, repository
`Universal-Dev-Security`, workflow `publish-pypi.yml`, environment `pypi`.

For each release: publish the GitHub release with its assets and `SHA256SUMS` first, then run
*Actions → publish to PyPI → Run workflow* with the tag. The workflow downloads the release
assets, verifies them against `SHA256SUMS`, runs `twine check --strict`, and uploads exactly
those files, so PyPI and GitHub serve identical artifacts. PyPI files are immutable: a mistake
requires a new version number.

## Versioning

Semantic Versioning. Pre-releases use PEP 440 suffixes (`1.0.0rc1`). The JSON
report carries its own `schema_version`; breaking schema changes bump its major version.
