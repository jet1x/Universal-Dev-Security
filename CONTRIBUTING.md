# Contributing

Thanks for your interest in Universal Dev Security.

## Ground rules

- Discuss substantial changes in an issue before implementing them.
- Never include real credentials, tokens, private keys, customer data or production data.
- Secret fixtures must be clearly fake **and assembled at runtime** (see `tests/fakes.py`) so
  that secret scanners running on this repository do not flag the test suite.
- Do not weaken mandatory global security policies. Policy changes need a test that shows the
  intended decision and must keep every existing global rule at least as strict.
- Never invent severities or scores. Map severity only from scanner data or a published standard,
  and record the provenance in `severity_source`.
- Never print, log or persist raw scanner output or secret values.
- Run external programs only through `scanners.base.run_tool()` (argument list, no shell).
- Keep regular expressions bounded; add a case to `tests/test_redos.py` for new patterns.

## Development setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"     # Windows: .venv\Scripts\python
.venv/bin/python -m pytest -q
```

Tests that need Git or Gitleaks are skipped automatically when those tools are absent; CI runs
them with real scanners on Linux.

## Pull requests

Explain the problem, affected modules, test results and security implications. Add tests for new
behavior and for every bug fix (regression test). Do not modify tests to hide implementation bugs,
and do not claim a scan or test passed unless it was actually run.

All contributions are licensed under Apache-2.0.
