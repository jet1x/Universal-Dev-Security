"""Sanitized JSON, SARIF and dark HTML dashboard reports.

Security properties:
* Every untrusted string is HTML-escaped; links are restricted to http(s).
* Embedded JSON escapes ``<``, ``>`` and ``&`` so it cannot terminate the script block.
* A Content-Security-Policy allows only the report's own inline script (by hash);
  no external resources, fonts, or CDNs are loaded.
* Reports contain finding metadata only — never secret values or raw scanner output.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from universal_dev_security import __version__
from universal_dev_security.findings import SEVERITY_ORDER

MAX_HTML_FINDINGS = 2000

INSTALL_HINTS = {
    "gitleaks": "https://github.com/gitleaks/gitleaks#installing",
    "semgrep": "https://semgrep.dev/docs/getting-started/quickstart",
    "osv-scanner": "https://google.github.io/osv-scanner/installation/",
    "trivy": "https://trivy.dev/latest/getting-started/installation/",
}


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------

def recommendations(scan: dict[str, Any], comparison: dict[str, Any] | None = None) -> list[dict[str, str]]:
    """Deterministic recommendations derived only from scan data."""
    recs: list[dict[str, str]] = []
    findings = scan.get("findings", [])
    secrets = [f for f in findings if f.get("category") == "secret"]
    committed = [f for f in secrets if f.get("tracked_in_git") is True]
    local_only = [f for f in secrets if f.get("tracked_in_git") is False]
    unknown = [f for f in secrets if f.get("tracked_in_git") is None]
    if committed:
        recs.append({"priority": "urgent", "title": f"Rotate {len(committed)} credential(s) found in Git-tracked files",
                     "detail": "These secrets are committed and shared with everyone who can access the repository. "
                               "Revoke or rotate each with its issuer first, then remove it from the code and plan "
                               "an approved Git history clean-up."})
    if unknown:
        recs.append({"priority": "urgent", "title": f"Rotate {len(unknown)} potentially exposed credential(s)",
                     "detail": "Revoke or rotate each credential with its issuer before removing it from code. "
                               "If it was committed, plan an approved Git history clean-up."})
    if local_only:
        files = sorted({str(f.get("file")) for f in local_only})
        shown = ", ".join(files[:5]) + (f" and {len(files) - 5} more file(s)" if len(files) > 5 else "")
        recs.append({"priority": "medium",
                     "title": f"{len(local_only)} potential secret(s) in local files not tracked by Git",
                     "detail": f"Found in {shown}. These have not been shared through Git. Keep the files "
                               "git-ignored and out of shared folders, and rotate any credential that was ever "
                               "committed, shared or published elsewhere."})
    deps = [f for f in findings if f.get("category") == "dependency"]
    fixable = sorted({f"{f.get('package')} → {f.get('fixed_version')}" for f in deps if f.get("fixed_version")})
    if fixable:
        shown = ", ".join(fixable[:8]) + (" …" if len(fixable) > 8 else "")
        recs.append({"priority": "high", "title": f"Upgrade {len(fixable)} vulnerable dependency version(s) with known fixes",
                     "detail": f"{shown}. Upgrade, then run the test suite (`uds test`)."})
    unfixed = [f for f in deps if not f.get("fixed_version")]
    if unfixed:
        recs.append({"priority": "medium", "title": f"Assess {len(unfixed)} dependency finding(s) without a published fix",
                     "detail": "Check exploitability in your usage, consider alternatives, and monitor advisories."})
    code = [f for f in findings if f.get("category") == "code" and f.get("severity") in ("critical", "high")]
    if code:
        recs.append({"priority": "high", "title": f"Review {len(code)} high/critical code finding(s)",
                     "detail": "Validate each finding and fix confirmed issues; add regression tests."})
    config = [f for f in findings if f.get("category") == "configuration"]
    if config:
        recs.append({"priority": "medium", "title": f"Harden {len(config)} configuration issue(s)",
                     "detail": "Apply the resolution listed on each configuration finding."})
    for scanner in scan.get("scanners", []):
        tool, status, reason = scanner.get("tool"), scanner.get("status"), scanner.get("reason")
        if status == "not_installed":
            recs.append({"priority": "coverage", "title": f"Install {tool} to extend coverage",
                         "detail": f"Official installation instructions: {INSTALL_HINTS.get(tool, '')}"})
        elif status == "skipped" and reason == "network_not_approved":
            recs.append({"priority": "coverage", "title": f"Approve network use for {tool} if acceptable",
                         "detail": str(scanner.get("message", ""))})
        elif status == "skipped":
            recs.append({"priority": "coverage", "title": f"{tool} was skipped", "detail": str(scanner.get("message", ""))})
        elif status == "error":
            recs.append({"priority": "coverage", "title": f"{tool} failed — results are incomplete",
                         "detail": str(scanner.get("message", ""))})
    if comparison and comparison.get("new"):
        recs.insert(0, {"priority": "urgent" if any(f.get("category") == "secret" for f in comparison["new"]) else "high",
                        "title": f"{len(comparison['new'])} new finding(s) since the previous scan",
                        "detail": "Prioritize newly introduced findings — they are usually cheapest to fix now."})
    if not recs and scan.get("overall_status") == "clean":
        recs.append({"priority": "info", "title": "No findings from the executed scanners",
                     "detail": "Keep scanning on every change; a clean result is not proof of security."})
    return recs


def build_report(scan: dict[str, Any], comparison: dict[str, Any] | None = None,
                 history: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    report = dict(scan)
    report["report_generated_at"] = datetime.now(timezone.utc).isoformat()
    report["recommendations"] = recommendations(scan, comparison)
    report["comparison"] = comparison
    report["history"] = history or []
    return report


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unclassified": "warning"}


def build_sarif(scan: dict[str, Any]) -> dict[str, Any]:
    runs = []
    for scanner in scan.get("scanners", []):
        if not scanner.get("executed"):
            continue
        tool = scanner["tool"]
        findings = [f for f in scan.get("findings", []) if f.get("tool") == tool]
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for f in findings:
            rules.setdefault(f["rule_id"], {
                "id": f["rule_id"],
                "shortDescription": {"text": str(f.get("title") or f["rule_id"])[:300]},
                **({"helpUri": f["references"][0]} if f.get("references") else {}),
            })
            level = "error" if f.get("category") == "secret" else _SARIF_LEVEL.get(f.get("severity", ""), "warning")
            text = str(f.get("message") or f.get("title") or f["rule_id"])
            if f.get("package"):
                text += f" [{f['package']} {f.get('installed_version') or ''}]"
            result: dict[str, Any] = {
                "ruleId": f["rule_id"],
                "level": level,
                "message": {"text": text[:1000]},
                "partialFingerprints": {"udsFingerprint/v1": f["fingerprint"]},
                "properties": {"uds-severity": f.get("severity"), "uds-severity-source": f.get("severity_source"),
                               "category": f.get("category")},
            }
            if f.get("file"):
                location: dict[str, Any] = {"artifactLocation": {"uri": f["file"]}}
                if f.get("start_line"):
                    location["region"] = {"startLine": max(1, int(f["start_line"]))}
                result["locations"] = [{"physicalLocation": location}]
            results.append(result)
        runs.append({
            "tool": {"driver": {"name": f"UDS / {tool}", "version": scanner.get("version") or "unknown",
                                "informationUri": INSTALL_HINTS.get(tool, "https://github.com"),
                                "rules": list(rules.values())}},
            "results": results,
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}


# ---------------------------------------------------------------------------
# HTML dashboard
# ---------------------------------------------------------------------------

def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _link(url: str) -> str:
    if not isinstance(url, str) or not url.lower().startswith(("https://", "http://")):
        return ""
    return f'<a href="{_e(url)}" rel="noopener noreferrer" target="_blank">{_e(url)}</a>'


STATUS_LABEL = {
    "clean": ("Clean", "ok"), "findings": ("Findings", "bad"), "incomplete": ("Incomplete coverage", "warn"),
    "error": ("Scan error", "bad"), "not_scanned": ("Not scanned", "warn"),
    "not_installed": ("Not installed", "warn"), "not_applicable": ("Not applicable", "muted"),
    "skipped": ("Skipped", "warn"),
}

CSS = """
:root{--bg:#080d18;--surface:#101a2b;--surface-2:#142238;--surface-3:#0c1524;--ink:#e8eef8;--muted:#9fb0c7;--line:#263750;
--accent:#55d6be;--accent-soft:#123a37;--sev-critical:#ff6b81;--sev-high:#ff9f68;--sev-medium:#f5c66a;--sev-low:#86b7ff;
--sev-unclassified:#b4bfce;--ok:#55d6be;--bad:#ff7b86;--warn:#f5c66a;--focus:#7fe9d6}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:radial-gradient(ellipse at 12% 0%,#13283f 0,transparent 36%),var(--bg);color:var(--ink);
font:14px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:#8fd8ff;overflow-wrap:anywhere}a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.skip{position:absolute;left:-999px}.skip:focus{left:16px;top:16px;background:var(--surface);padding:8px;z-index:9}
main{max-width:1200px;margin:0 auto;padding:32px 20px 56px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px;font-weight:750;letter-spacing:.02em}
.mark{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,#1b766d,#174b65);color:#d9fff8;font-size:19px}
.eyebrow{color:var(--accent);font-size:11px;font-weight:750;letter-spacing:.14em;text-transform:uppercase}
h1{font-size:clamp(24px,4vw,32px);line-height:1.2;margin:6px 0;letter-spacing:-.03em}h2{font-size:17px;margin:0}h3{font-size:13px;margin:0 0 6px}
.muted{color:var(--muted);overflow-wrap:anywhere}
.card{background:linear-gradient(160deg,rgba(18,30,49,.97),rgba(13,23,38,.97));border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:16px}
.head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 18px;margin-top:14px;font-size:13px}
.meta b{color:var(--muted);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:5px 11px;font-size:12px;font-weight:700;letter-spacing:.03em;white-space:nowrap}
.pill:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.ok{color:var(--ok);background:var(--accent-soft);border-color:#28645b}.bad{color:var(--bad);background:#3b202b80;border-color:#713642}
.warn{color:var(--warn);background:#3a302080;border-color:#66532c}.muted-pill{color:var(--muted);background:#1a2637}
.sev-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}
.stat{background:var(--surface-3);border:1px solid var(--line);border-radius:12px;padding:14px;border-top:3px solid var(--line)}
.stat .label{font-size:12px;color:var(--muted)}.stat .value{font-size:26px;font-weight:760;line-height:1.2;margin-top:6px}
.stat.critical{border-top-color:var(--sev-critical)}.stat.high{border-top-color:var(--sev-high)}.stat.medium{border-top-color:var(--sev-medium)}
.stat.low{border-top-color:var(--sev-low)}.stat.unclassified{border-top-color:var(--sev-unclassified)}.stat.total{border-top-color:var(--accent)}
.sev{display:inline-block;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.04em;color:#0b1220}
.sev-critical{background:var(--sev-critical)}.sev-high{background:var(--sev-high)}.sev-medium{background:var(--sev-medium)}
.sev-low{background:var(--sev-low)}.sev-unclassified{background:var(--sev-unclassified)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--surface-2);color:#b3c3d8;font-size:11px;text-transform:uppercase;letter-spacing:.08em}tbody tr:last-child td{border-bottom:0}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#9bd9ff;font-size:12px;overflow-wrap:anywhere}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
input,select,button{background:#0b1524;color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:9px 12px;font:inherit}
input{flex:1;min-width:200px}button{cursor:pointer;font-weight:650}button:hover{border-color:var(--accent)}
.finding{border:1px solid var(--line);border-radius:12px;margin-bottom:8px;background:var(--surface-3)}
.finding summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
.finding summary::-webkit-details-marker{display:none}.finding summary:before{content:"▸";color:var(--muted)}.finding[open] summary:before{content:"▾"}
.finding .title{font-weight:650;flex:1;min-width:200px}.finding .loc{font-size:12px;color:var(--muted)}
.finding .body{padding:0 16px 14px 34px;display:grid;gap:6px}.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}
.finding dt{color:var(--muted);font-size:12px}.finding dd{margin:0;overflow-wrap:anywhere}
.tag{display:inline-flex;border:1px solid var(--line);border-radius:7px;padding:2px 7px;color:#c2d0e2;background:#132238;font-size:11px;font-weight:700}
.tag-bad{color:var(--bad);background:#3b202b80;border-color:#713642}
.rec{border-left:3px solid var(--accent);background:#0f2a2f;padding:10px 14px;border-radius:0 10px 10px 0;margin-bottom:8px}
.rec.urgent{border-left-color:var(--sev-critical);background:#2c1620}.rec.high{border-left-color:var(--sev-high);background:#2b1d16}
.rec.coverage{border-left-color:var(--warn);background:#2a2416}.rec .p{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
ul{padding-left:19px;margin:6px 0 0;color:var(--muted)}footer{color:#7d8ea6;font-size:12px;text-align:center;padding:16px}
.empty{color:var(--muted);text-align:center;padding:20px}
@media(max-width:900px){.sev-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.grid2{grid-template-columns:1fr}}
@media(max-width:520px){main{padding:18px 14px 36px}.card{padding:16px}.sev-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.finding .body{padding-left:16px}}
@media print{body{background:#fff;color:#000}.controls,.skip{display:none}.card{border-color:#999;background:#fff}}
"""

SCRIPT = """(function(){
var q=document.getElementById('search'),sv=document.getElementById('severity-filter'),tl=document.getElementById('tool-filter'),
ct=document.getElementById('category-filter'),cnt=document.getElementById('visible-count');
var items=[].slice.call(document.querySelectorAll('#findings-list .finding'));
function filter(){var t=(q.value||'').toLowerCase(),s=sv.value,o=tl.value,c=ct.value,n=0;
items.forEach(function(el){var ok=(!t||el.textContent.toLowerCase().indexOf(t)>-1)&&(!s||el.dataset.severity===s)&&(!o||el.dataset.tool===o)&&(!c||el.dataset.category===c);
el.hidden=!ok;if(ok)n++;});cnt.textContent=n+' shown';}
[q,sv,tl,ct].forEach(function(el){el.addEventListener('input',filter);el.addEventListener('change',filter);});
document.getElementById('expand-all').addEventListener('click',function(){var open=this.getAttribute('aria-pressed')!=='true';
items.forEach(function(el){if(!el.hidden)el.open=open;});this.setAttribute('aria-pressed',String(open));this.textContent=open?'Collapse all':'Expand all';});
function save(name,type,text){var b=new Blob([text],{type:type}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;
document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},0);}
document.getElementById('export-json').addEventListener('click',function(){save('uds-security-report.json','application/json',document.getElementById('uds-data').textContent);});
document.getElementById('export-html').addEventListener('click',function(){save('uds-security-report.html','text/html','<!doctype html>\\n'+document.documentElement.outerHTML);});
})();"""


def _status_pill(status: str) -> str:
    label, cls = STATUS_LABEL.get(status, (status.replace("_", " ").title(), "warn"))
    cls = "muted-pill" if cls == "muted" else cls
    return f'<span class="pill {cls}">{_e(label)}</span>'


def _exposure(f: dict[str, Any]) -> str | None:
    if f.get("category") != "secret" or f.get("tracked_in_git") is None:
        return None
    return "in-git" if f["tracked_in_git"] else "local"


def _finding_html(f: dict[str, Any]) -> str:
    sev = f.get("severity", "unclassified")
    loc = f.get("file") or "—"
    if f.get("start_line"):
        loc += f":{f['start_line']}"
    rows = [("Rule", f"<code>{_e(f.get('rule_id'))}</code>"), ("Scanner", _e(f.get("tool"))),
            ("Category", _e(f.get("category"))), ("Location", f"<code>{_e(loc)}</code>")]
    if f.get("package"):
        rows.append(("Package", _e(f"{f['package']} {f.get('installed_version') or ''}")))
        rows.append(("Fixed in", _e(f.get("fixed_version") or "No fix listed")))
    if f.get("commit"):
        rows.append(("Commit", f"<code>{_e(f['commit'])}</code>"))
    exposure = _exposure(f)
    if exposure:
        rows.append(("Git exposure", _e({"in-git": "Tracked by Git — committed and shared",
                                         "local": "Not tracked by Git — local file only"}[exposure])))
    source = f.get("severity_source", "none")
    sev_note = {"scanner": "reported by scanner", "cvss-qualitative-scale": "CVSS qualitative scale",
                "advisory-database": "advisory database", "none": "no validated severity available"}.get(source, source)
    rows.append(("Severity", f"{_e(sev)} <span class='muted'>({_e(sev_note)}"
                             + (f"; scanner value: {_e(f['scanner_severity'])}" if f.get("scanner_severity") else "")
                             + ")</span>"))
    if f.get("message"):
        rows.append(("Details", _e(f["message"])))
    if f.get("remediation"):
        rows.append(("Remediation", _e(f["remediation"])))
    links = [link for link in (_link(r) for r in f.get("references", [])[:5]) if link]
    if links:
        rows.append(("References", "<br>".join(links)))
    rows.append(("Fingerprint", f"<code>{_e(f.get('fingerprint'))}</code>"))
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (f'<details class="finding" data-severity="{_e(sev)}" data-tool="{_e(f.get("tool"))}" '
            f'data-category="{_e(f.get("category"))}"><summary><span class="sev sev-{_e(sev)}">{_e(sev)}</span>'
            f'<span class="title">{_e(f.get("title") or f.get("rule_id"))}</span>'
            + ({"in-git": '<span class="tag tag-bad">in Git</span>',
                "local": '<span class="tag">local only</span>'}.get(exposure or "", ""))
            + f'<span class="tag">{_e(f.get("tool"))}</span><span class="loc">{_e(loc)}</span></summary>'
            f'<div class="body"><dl>{dl}</dl></div></details>')


def _comparison_html(comparison: dict[str, Any] | None) -> str:
    if not comparison:
        return ('<p class="muted">No previous scan in history to compare with. Comparison appears after the next scan.</p>')
    new, resolved = comparison.get("new", []), comparison.get("resolved", [])
    stats = (f'<div class="sev-grid" style="grid-template-columns:repeat(4,minmax(0,1fr))">'
             f'<div class="stat high"><div class="label">New</div><div class="value">{len(new)}</div></div>'
             f'<div class="stat total"><div class="label">Resolved</div><div class="value">{len(resolved)}</div></div>'
             f'<div class="stat unclassified"><div class="label">Unchanged</div><div class="value">{comparison.get("unchanged_count", 0)}</div></div>'
             f'<div class="stat medium"><div class="label">Not re-scanned</div><div class="value">{len(comparison.get("not_rescanned", []))}</div></div></div>')
    items = "".join(
        f'<tr><td><span class="sev sev-{_e(f.get("severity"))}">{_e(f.get("severity"))}</span></td><td>{_e(f.get("title"))}</td>'
        f'<td><code>{_e(f.get("file"))}</code></td><td>{_e(label)}</td></tr>'
        for label, group in (("new", new[:50]), ("resolved", resolved[:50])) for f in group
    )
    table = (f'<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Severity</th><th>Finding</th><th>File</th>'
             f'<th>Change</th></tr></thead><tbody>{items}</tbody></table></div>') if items else ""
    warnings = "".join(f'<div class="rec coverage"><div class="p">scope changed</div>{_e(w)}</div>'
                       for w in comparison.get("warnings", []))
    return (f'<p class="muted">Compared with scan <code>{_e(comparison.get("base_scan_id"))}</code> for '
            f'{_e(", ".join(comparison.get("compared_tools", [])) or "no common scanners")}.</p>'
            f'{warnings}{stats}{table}'
            f'<p class="muted" style="font-size:12px">{_e(comparison.get("note"))}</p>')


def _history_html(history: list[dict[str, Any]]) -> str:
    if not history:
        return '<p class="muted">No scan history yet.</p>'
    rows = []
    for entry in reversed(history[-20:]):
        sev = entry.get("by_severity", {})
        cells = "".join(f"<td>{_e(sev.get(s.value, 0))}</td>" for s in SEVERITY_ORDER)
        rows.append(f'<tr><td><code>{_e(entry.get("scan_id"))}</code></td><td>{_status_pill(str(entry.get("overall_status")))}</td>'
                    f'<td>{_e(entry.get("finding_count"))}</td>{cells}<td>{_e(", ".join(entry.get("executed", [])))}</td></tr>')
    head = "".join(f"<th>{_e(s.value.title())}</th>" for s in SEVERITY_ORDER)
    return (f'<div class="table-wrap"><table><thead><tr><th>Scan</th><th>Status</th><th>Total</th>{head}<th>Scanners run</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    by_sev = summary.get("by_severity", {})
    findings = report.get("findings", [])
    shown = findings[:MAX_HTML_FINDINGS]
    status = str(report.get("overall_status", "unknown"))

    sev_cards = (f'<div class="stat total"><div class="label">Total findings</div><div class="value">{_e(summary.get("finding_count", 0))}</div></div>'
                 + "".join(f'<div class="stat {s.value}"><div class="label">{_e(s.value.title())}</div>'
                           f'<div class="value">{_e(by_sev.get(s.value, 0))}</div></div>' for s in SEVERITY_ORDER))

    scanner_rows = "".join(
        f'<tr><td><b>{_e(s.get("tool"))}</b></td><td>{_status_pill(str(s.get("status")))}</td><td>{_e(s.get("version") or "—")}</td>'
        f'<td>{_e(s.get("finding_count")) if s.get("executed") else "—"}</td><td class="muted">{_e(s.get("message"))}</td></tr>'
        for s in report.get("scanners", [])
    )
    privacy_rows = "".join(
        f'<li><b>{_e(p.get("tool"))}</b>: {_e(p.get("note"))}</li>' for p in report.get("privacy", []) if p.get("note")
    )
    recs = "".join(
        f'<div class="rec {_e(r.get("priority"))}"><div class="p">{_e(r.get("priority"))}</div><b>{_e(r.get("title"))}</b>'
        f'<div class="muted">{_e(r.get("detail"))}</div></div>' for r in report.get("recommendations", [])
    ) or '<p class="muted">No recommendations.</p>'

    tools = sorted({str(f.get("tool")) for f in findings})
    categories = sorted({str(f.get("category")) for f in findings})
    tool_opts = "".join(f'<option value="{_e(t)}">{_e(t)}</option>' for t in tools)
    cat_opts = "".join(f'<option value="{_e(c)}">{_e(c.title())}</option>' for c in categories)
    sev_opts = "".join(f'<option value="{s.value}">{s.value.title()}</option>' for s in SEVERITY_ORDER)
    finding_items = "".join(_finding_html(f) for f in shown) or \
        '<p class="empty">No findings were returned by the scanners that executed.</p>'
    truncated = (f'<p class="muted">Showing the first {MAX_HTML_FINDINGS} of {len(findings)} findings. '
                 'The JSON report contains all findings.</p>') if len(findings) > len(shown) else ""
    limitations = "".join(f"<li>{_e(item)}</li>" for item in report.get("limitations", []))
    project = report.get("project", {})

    data = json.dumps(report, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
    csp = (f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'; "
           "img-src data:; base-uri 'none'; form-action 'none'")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_e(csp)}">
<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark">
<title>UDS Security Dashboard</title><style>{CSS}</style></head><body>
<a class="skip" href="#findings">Skip to findings</a>
<main>
<div class="topbar"><div class="brand"><div class="mark" aria-hidden="true">⬡</div><div>UNIVERSAL DEV SECURITY
<div class="muted" style="font-size:11px;font-weight:500">One Security System. Every Project.</div></div></div>
<div class="controls" style="margin:0"><button type="button" id="export-json">Export JSON</button>
<button type="button" id="export-html">Export HTML</button></div></div>

<header class="card"><div class="head"><div><div class="eyebrow">Security overview</div><h1>Security dashboard</h1>
<div class="muted">Results from locally executed scanners. Severity is never inferred.</div></div>{_status_pill(status)}</div>
<div class="meta"><div><b>Target</b> · <span class="muted">{_e(report.get("target"))}</span></div>
<div><b>Scan</b> · <code>{_e(report.get("scan_id"))}</code></div>
<div><b>Started</b> · {_e(report.get("started_at"))}</div>
<div><b>Technologies</b> · {_e(", ".join(project.get("detected", [])))}</div>
<div><b>UDS</b> · {_e(report.get("uds_version"))}</div>
<div><b>Security score</b> · Not calculated <span class="muted">(no validated methodology)</span></div></div></header>

<section class="card" aria-labelledby="sev-h"><div class="head"><h2 id="sev-h">Findings by severity</h2></div>
<div class="sev-grid">{sev_cards}</div></section>

<div class="grid2">
<section class="card" aria-labelledby="rec-h"><div class="head"><h2 id="rec-h">Recommendations</h2></div>{recs}</section>
<section class="card" aria-labelledby="cmp-h"><div class="head"><h2 id="cmp-h">Change since previous scan</h2></div>{_comparison_html(report.get("comparison"))}</section>
</div>

<section class="card" aria-labelledby="cov-h"><div class="head"><h2 id="cov-h">Scanner coverage</h2></div>
<div class="table-wrap"><table><thead><tr><th>Scanner</th><th>Status</th><th>Version</th><th>Findings</th><th>Details</th></tr></thead>
<tbody>{scanner_rows}</tbody></table></div>
<ul>{privacy_rows}</ul></section>

<section class="card" id="findings" aria-labelledby="find-h"><div class="head"><h2 id="find-h">Findings</h2>
<span class="pill muted-pill" id="visible-count" aria-live="polite">{len(shown)} shown</span></div>
<div class="controls"><input id="search" type="search" placeholder="Search title, rule, file, package…" aria-label="Search findings">
<select id="severity-filter" aria-label="Filter by severity"><option value="">All severities</option>{sev_opts}</select>
<select id="tool-filter" aria-label="Filter by scanner"><option value="">All scanners</option>{tool_opts}</select>
<select id="category-filter" aria-label="Filter by category"><option value="">All categories</option>{cat_opts}</select>
<button type="button" id="expand-all" aria-pressed="false">Expand all</button></div>
{truncated}<div id="findings-list">{finding_items}</div></section>

<section class="card" aria-labelledby="hist-h"><div class="head"><h2 id="hist-h">Scan history</h2></div>{_history_html(report.get("history", []))}</section>

<section class="card" aria-labelledby="lim-h"><h2 id="lim-h">Coverage &amp; limitations</h2><ul>{limitations}</ul>
<p class="muted" style="font-size:12px">{_e(summary.get("score_note"))}</p></section>
<footer>Generated locally by UDS {_e(__version__)} · Secret values and raw scanner output are intentionally excluded.</footer>
</main>
<script type="application/json" id="uds-data">{data}</script>
<script>{SCRIPT}</script></body></html>"""


def write_reports(report: dict[str, Any], target: Path, report_dir: Path | None = None,
                  formats: tuple[str, ...] = ("json", "html")) -> dict[str, str]:
    """Write the requested report formats; return their paths."""
    root = target.expanduser().resolve()
    if report_dir is None:
        from universal_dev_security.history import ensure_uds_dir
        ensure_uds_dir(root)
        destination = root / ".uds" / "reports"
    else:
        destination = report_dir.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    if "json" in formats:
        path = destination / "security-report.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        paths["json"] = str(path)
    if "html" in formats:
        path = destination / "security-report.html"
        path.write_text(render_html(report), encoding="utf-8", newline="\n")
        paths["html"] = str(path)
    if "sarif" in formats:
        path = destination / "security-report.sarif"
        path.write_text(json.dumps(build_sarif(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        paths["sarif"] = str(path)
    return paths
