# Universal Dev Security — Mandatory Global Security Policy

This policy is the non-negotiable baseline for every UDS-managed project.
Technology and project profiles may add stricter requirements but must not
weaken this baseline.

## 1. Secrets and credentials
- Never commit real passwords, API keys, tokens, private keys, connection strings, or session secrets.
- Use environment variables or an approved secret manager.
- If a likely secret is detected in content intended for Git, block the operation and redact the value in reports.
- Do not automatically rewrite Git history or rotate credentials without user approval.

## 2. Secure coding
- Prefer safe APIs and validate untrusted input at trust boundaries.
- Apply context-appropriate output encoding and parameterized database queries.
- Avoid unsafe deserialization, command injection, path traversal, and insecure cryptography.
- Findings must include evidence, file/line references where available, severity, and remediation guidance.

## 3. Privacy and data protection
- Collect and retain only data required for the stated function.
- Do not transmit project source, reports, or telemetry without explicit user consent.
- Redact secrets and sensitive values from logs and reports.

## 4. Authentication and authorization
- Enforce server-side authorization; never rely only on client-side checks.
- Apply least privilege and secure session/token handling.
- Do not invent or silently weaken authentication controls.

## 5. Quality and compatibility
- Preserve existing functionality and user changes.
- Explain changes and affected files.
- Avoid unrelated refactors during security fixes.

## 6. Testing
- Run relevant existing tests after changes.
- If no tests exist, propose or create minimal appropriate tests and run them.
- Never report a test or scan as passed unless it actually ran successfully.

## 7. Destructive actions
- Do not delete user data, rewrite Git history, force-push, or run destructive migrations without explicit approval.
- Create a recoverable checkpoint before automated modifications where practical.
- Roll back only UDS-owned changes; preserve unrelated user work.

## 8. Dependencies and supply chain
- Identify dependency sources and lockfiles.
- Report known vulnerabilities and distinguish direct from transitive dependencies.
- Do not upgrade dependencies blindly; assess compatibility and test the result.

## 9. Git and remote operations
- Inspect staged changes before commit.
- Scan staged content and outgoing commits where supported.
- Block pushes when confirmed secrets or configured critical policy violations are present.
- Never commit or push without explicit user approval.
- Local hooks are defense-in-depth and may be bypassed; use independent CI and repository controls too.

## 10. Risk-based remediation
- Low risk: automatic fix may proceed with tests and a recoverable checkpoint.
- Medium risk: proceed automatically only when scope is clear, reversible, and tests are available; otherwise ask.
- High/critical risk: stop the risky operation and request user approval.
- If repair fails, restore UDS-owned changes where safe and report the result.

## 11. Configuration precedence
Mandatory global policy > technology profile > project configuration.
Lower-level settings may add restrictions but cannot disable mandatory global rules.

## 12. Honest reporting
- Clearly distinguish detected, not detected, not scanned, and scan failed.
- Never claim complete security or guarantee absence of vulnerabilities.
- Mask secret values in terminal output, logs, and reports.

## 13. Enforcement in UDS 1.0
This policy is enforced, not only documented:
- `src/universal_dev_security/policy.py` implements the command and file rules (sections 1, 7, 9, 10, 11).
- Git hooks (`uds hooks install`) block secrets in staged changes and outgoing commits (sections 1, 9).
- The Claude Code hook and `uds guard` apply the same engine to AI agents; they never auto-approve (sections 7, 9, 11).
- `uds fix` applies only low-risk fixes by default, with a checkpoint and test verification (sections 6, 7, 10).
- Scanner states and report wording follow section 12; severity is never inferred.
`uds policy show` prints the active rules for a project.
