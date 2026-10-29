# Curated Scout review knowledge

Collected and inspected on 2026-10-27. The authoritative file-level lock is
`data/review_sources.json`: 14 repositories, full commit revisions, 72 inspected
file paths, byte counts, SHA-256 and Git blob SHA-1 identities. SHA-1 is recorded
as the Git object identity in addition to SHA-256, not as a signature or author
attestation. A truncated CodeQL tree response is recorded explicitly; only the
selected files, not a full CodeQL inventory, were inspected.

`data/review_topics.json` contains 52 original Scout review topics and 104 authored
risk/benign scenarios. These are review knowledge, not imported detectors,
executable test fixtures, measured recall, or a claim of upstream equivalence.
All checks/remediations/scenarios and compact prompt hints were written for
Scout. No upstream code, regexes, YARA, prompts, allowlists, fixes or example
programs are copied into this extension. Historical NVIDIA-derived assets keep
their independent attribution in `skillspector.md` and the existing NOTICE.

## Selection

- Go: gosec and CodeQL for command/argument boundaries, requests, paths, archives,
  SQL and TLS; Cisco for credential collection/egress context.
- JavaScript/TypeScript: CodeQL for command/code injection, prototypes and SSRF;
  Cisco for data movement and installation behavior; njsscan as a reference
  cross-check of Node process and vm threats. TypeScript is reviewed as runtime
  JavaScript where applicable; annotations alone do not validate input.
- Python: Bandit for shell modes, loaders, SQL and archive extraction; CodeQL for
  path boundaries; Cisco for collection and execution-chain context.
- Shell: ShellCheck as a reference for expansion, command argument semantics,
  eval/sourcing and destructive operations; Cisco for remote execution/egress.
- Language-independent: Cisco, MCP specification/security guidance, OpenSSF
  Scorecard and Gitleaks for agent/tool trust, secrets, provenance, CI authority,
  token/session boundaries and inspection limits. OWASP MCP is a taxonomy
  cross-check, not copied documentation or a new compliance claim.
- Other languages: selected DevSkim/CodeQL references for object/XML loading,
  security randomness and native format-string boundaries.

- SQL: OWASP SQL/database cheat sheets and PostgreSQL 18 documentation as
  reference-only sources for value binding, dynamic queries, roles/RLS,
  destructive migrations, server/client exports, logging and time/resource bounds.
  Existing Go/Python SQL guidance is retained; JS/TS query construction also
  references the inspected CodeQL SQL help. PostgreSQL-specific semantics are
  explicitly scoped to that engine.

## Reuse and limitations

`declared_license` records the inspected source statement, not a license
clearance. Semgrep's README/license were evaluated; its executable rules were
not imported and are not cited as inspected topic implementations. ShellCheck,
njsscan, MCP and OWASP are reference-only. In particular, the pinned MCP LICENSE
describes an Apache/MIT transition and CC-BY-4.0 documentation, and OWASP's
LICENSE.md and index.md make inconsistent CC-BY-SA/CC-BY-NC-SA declarations.
These uncertainties remain visible in the exported source registry.

No source's suppression heuristics, confidence values or severity are adopted.
Documentation/example context is a consideration, not a trusted exemption.
Related rule IDs associate guidance only; they do not grant a detector the
source tool's AST, interprocedural analysis, effective loader semantics or
coverage. Source links are not evidence citations for model findings.

All data is compiled into Scout and included in its knowledge manifest digest.
Runtime never fetches a source, executes the scenarios, or reads policy from a
target. `internal/dev/maintenance/sources.go` can recheck the inspected snapshots
from a SHA-256-named cache; `--download` explicitly opts into fetching pinned
public bytes for maintenance only.


Runtime integration v4: discovery can return compiled `knowledge:<topic ID>`
reasons. Scout resolves their original guidance and provenance for proposal
verification and reports. This is a semantic-output contract extension, not an
upstream detector port or proof of model quality.
