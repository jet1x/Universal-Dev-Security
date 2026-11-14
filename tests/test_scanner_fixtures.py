"""Regression tests against real scanner output captured during development.

Fixtures were produced by OSV-Scanner 2.7.1 and Trivy 0.76.2 (official
releases, checksum-verified) on a sample project, trimmed, and scrubbed of
absolute paths.
"""
import json
from pathlib import Path

from universal_dev_security.findings import Severity
from universal_dev_security.scanners import osv, trivy

FIXTURES = Path(__file__).parent / "fixtures"


def load(name, root=None):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    if root is not None:
        # Scanners report absolute paths for the scanned project; recreate that on this OS.
        text = text.replace('"/project/', json.dumps(str(root) + "/")[:-1])
    return json.loads(text)


def test_real_osv_output_normalizes(tmp_path):
    findings = osv.normalize(load("osv-scanner-2.7.1.json", tmp_path), tmp_path)
    assert findings, "expected findings from fixture"
    for f in findings:
        assert f.tool == "osv-scanner" and f.package == "jinja2" and f.installed_version == "2.4.1"
        assert f.file == "requirements.txt"
        assert f.rule_id.startswith(("GHSA-", "PYSEC-", "CVE-"))
        assert f.references[0].startswith("https://osv.dev/vulnerability/")
        assert len(f.references) == len(set(f.references))
        if f.severity is not Severity.UNCLASSIFIED:
            assert f.severity_source in ("cvss-qualitative-scale", "advisory-database")
    assert any(f.fixed_version for f in findings)


def test_real_trivy_output_normalizes():
    findings = trivy.normalize(load("trivy-0.76.2.json"), Path("/project"))
    vulns = [f for f in findings if f.category.value == "dependency"]
    misconfigs = [f for f in findings if f.category.value == "configuration"]
    assert vulns and misconfigs
    assert all(f.severity_source == "scanner" for f in findings if f.severity is not Severity.UNCLASSIFIED)
    root_user = [f for f in misconfigs if "root" in f.title.lower()]
    assert root_user and root_user[0].severity is Severity.HIGH and root_user[0].file == "Dockerfile"
    for f in findings:
        assert len(f.references) == len(set(f.references))
