# Security policy

Report vulnerabilities privately before publishing exploit details, credentials
or sensitive scan inputs. This includes scanner crashes, consent bypasses,
unintended code execution and disclosure of inspected source data.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/skarm/scout/security/advisories/new)
when GitHub offers it for this repository. If private reporting is unavailable,
open an [issue](https://github.com/skarm/scout/issues/new) requesting a private
security contact. Include no vulnerability details or sensitive attachments in
that public request; wait for a private channel before sending them.

In the private report, include the Scout version or commit, operating system,
build mode, reproduction steps, expected and observed behavior, and likely impact.
Prefer a minimal inert fixture with synthetic credentials. Redact secrets and
obtain permission before sharing someone else's source code.

## Fixes and disclosure

Security fixes target the current default branch. Older commits and releases have
no separate maintenance commitment. Coordinate public disclosure with the
maintainer through the private report; no response-time guarantee is specified.

Scout's findings and fixed regression tests do not establish that an inspected
package is safe. Report incomplete inspections and reproducible detection gaps
with the relevant configuration and a minimal example.
