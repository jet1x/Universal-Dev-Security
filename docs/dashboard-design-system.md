# UDS Dashboard Design System

Version: 1.0.0rc1

## Product surfaces

- **Available now:** a locally generated, self-contained, responsive dark HTML dashboard
  (`.uds/reports/security-report.html`), plus JSON and SARIF exports.
- **Prepared for later:** the same tokens and the JSON schema `2.0` contract for a future
  web dashboard. No hosted application is included.

## Visual direction

Dark-first security operations interface: navy surfaces, cool neutral text, teal
accent, and semantic severity colors. Status is never conveyed by color alone —
every badge carries a text label.

## Design tokens

| Token | Value | Purpose |
|---|---|---|
| `--bg` | `#080d18` | Page canvas |
| `--surface` / `--surface-2` / `--surface-3` | `#101a2b` / `#142238` / `#0c1524` | Panels, table headers, inset cards |
| `--ink` / `--muted` | `#e8eef8` / `#9fb0c7` | Primary / secondary text |
| `--line` | `#263750` | Borders and dividers |
| `--accent` | `#55d6be` | Brand, clean status, focus |
| `--sev-critical` | `#ff6b81` | Critical |
| `--sev-high` | `#ff9f68` | High |
| `--sev-medium` | `#f5c66a` | Medium |
| `--sev-low` | `#86b7ff` | Low |
| `--sev-unclassified` | `#b4bfce` | Unclassified |
| `--ok` / `--bad` / `--warn` | `#55d6be` / `#ff7b86` / `#f5c66a` | Scan status pills |
| `--focus` | `#7fe9d6` | Keyboard focus outline |

## Components

1. Top bar with product identity and **Export JSON / Export HTML** buttons.
2. Overview header: overall status, target, scan id, start time, technologies, UDS version,
   explicit "Security score: Not calculated".
3. Severity cards: Total, Critical, High, Medium, Low, Unclassified.
4. Recommendations (urgent / high / medium / coverage), derived only from scan data.
5. Change since previous scan: new, resolved, unchanged, not re-scanned + change table.
6. Scanner coverage table with status, version, findings and privacy notes.
7. Findings: search, severity / scanner / category filters, expand-all, expandable details
   (rule, location, package, fixed version, severity source, remediation, references, fingerprint).
8. Scan history table (last 20 scans).
9. Coverage & limitations.

## Security and accessibility requirements

- Escape all untrusted values; allow only http(s) links with `rel="noopener noreferrer"`.
- No external scripts, fonts or CDNs. CSP: `default-src 'none'`, script allowed by SHA-256 hash.
- Never include raw scanner output, secret values or source snippets.
- Do not infer severity or calculate a score without a validated, documented methodology.
- Skip link, labelled controls, `aria-live` result count, visible focus, print styles,
  responsive layout down to 360 px.
